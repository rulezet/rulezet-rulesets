rule TTP_XOR_WriteProcessMemory_48e7 {
  strings:
    $key_48e7 = { 1f 95 [2] 2d b7 [2] 2b 82 [2] 05 82 [2] 3a 9e }

  condition:
    any of them
}