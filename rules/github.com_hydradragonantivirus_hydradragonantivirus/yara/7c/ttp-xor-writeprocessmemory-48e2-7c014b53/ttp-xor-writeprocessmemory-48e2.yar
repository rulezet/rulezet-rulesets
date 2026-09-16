rule TTP_XOR_WriteProcessMemory_48e2 {
  strings:
    $key_48e2 = { 1f 90 [2] 2d b2 [2] 2b 87 [2] 05 87 [2] 3a 9b }

  condition:
    any of them
}