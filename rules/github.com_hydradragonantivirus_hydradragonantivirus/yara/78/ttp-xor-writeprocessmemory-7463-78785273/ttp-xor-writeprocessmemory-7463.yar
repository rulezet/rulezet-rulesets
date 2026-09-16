rule TTP_XOR_WriteProcessMemory_7463 {
  strings:
    $key_7463 = { 23 11 [2] 11 33 [2] 17 06 [2] 39 06 [2] 06 1a }

  condition:
    any of them
}