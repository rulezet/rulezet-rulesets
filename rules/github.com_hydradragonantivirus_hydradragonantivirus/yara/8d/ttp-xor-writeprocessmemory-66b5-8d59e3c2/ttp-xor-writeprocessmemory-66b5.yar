rule TTP_XOR_WriteProcessMemory_66b5 {
  strings:
    $key_66b5 = { 31 c7 [2] 03 e5 [2] 05 d0 [2] 2b d0 [2] 14 cc }

  condition:
    any of them
}