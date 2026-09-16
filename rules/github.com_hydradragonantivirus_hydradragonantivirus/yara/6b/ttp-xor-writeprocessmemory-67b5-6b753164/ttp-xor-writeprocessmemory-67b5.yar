rule TTP_XOR_WriteProcessMemory_67b5 {
  strings:
    $key_67b5 = { 30 c7 [2] 02 e5 [2] 04 d0 [2] 2a d0 [2] 15 cc }

  condition:
    any of them
}