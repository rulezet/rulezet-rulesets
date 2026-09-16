rule TTP_XOR_WriteProcessMemory_5242 {
  strings:
    $key_5242 = { 05 30 [2] 37 12 [2] 31 27 [2] 1f 27 [2] 20 3b }

  condition:
    any of them
}