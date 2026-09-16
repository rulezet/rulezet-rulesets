rule TTP_XOR_WriteProcessMemory_6062 {
  strings:
    $key_6062 = { 37 10 [2] 05 32 [2] 03 07 [2] 2d 07 [2] 12 1b }

  condition:
    any of them
}