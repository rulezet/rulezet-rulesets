rule TTP_XOR_WriteProcessMemory_48e0 {
  strings:
    $key_48e0 = { 1f 92 [2] 2d b0 [2] 2b 85 [2] 05 85 [2] 3a 99 }

  condition:
    any of them
}