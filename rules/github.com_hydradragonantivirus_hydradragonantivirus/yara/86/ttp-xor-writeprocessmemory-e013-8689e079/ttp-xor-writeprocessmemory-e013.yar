rule TTP_XOR_WriteProcessMemory_e013 {
  strings:
    $key_e013 = { b7 61 [2] 85 43 [2] 83 76 [2] ad 76 [2] 92 6a }

  condition:
    any of them
}