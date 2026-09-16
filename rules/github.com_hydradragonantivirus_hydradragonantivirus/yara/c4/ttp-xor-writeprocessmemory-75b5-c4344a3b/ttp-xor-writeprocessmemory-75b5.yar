rule TTP_XOR_WriteProcessMemory_75b5 {
  strings:
    $key_75b5 = { 22 c7 [2] 10 e5 [2] 16 d0 [2] 38 d0 [2] 07 cc }

  condition:
    any of them
}