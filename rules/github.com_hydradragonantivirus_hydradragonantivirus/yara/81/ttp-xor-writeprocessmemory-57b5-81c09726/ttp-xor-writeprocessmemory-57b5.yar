rule TTP_XOR_WriteProcessMemory_57b5 {
  strings:
    $key_57b5 = { 00 c7 [2] 32 e5 [2] 34 d0 [2] 1a d0 [2] 25 cc }

  condition:
    any of them
}