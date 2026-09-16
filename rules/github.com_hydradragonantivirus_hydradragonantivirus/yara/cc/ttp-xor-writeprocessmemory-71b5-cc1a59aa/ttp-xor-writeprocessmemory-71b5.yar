rule TTP_XOR_WriteProcessMemory_71b5 {
  strings:
    $key_71b5 = { 26 c7 [2] 14 e5 [2] 12 d0 [2] 3c d0 [2] 03 cc }

  condition:
    any of them
}