rule TTP_XOR_WriteProcessMemory_e042 {
  strings:
    $key_e042 = { b7 30 [2] 85 12 [2] 83 27 [2] ad 27 [2] 92 3b }

  condition:
    any of them
}