rule TTP_XOR_WriteProcessMemory_6d42 {
  strings:
    $key_6d42 = { 3a 30 [2] 08 12 [2] 0e 27 [2] 20 27 [2] 1f 3b }

  condition:
    any of them
}