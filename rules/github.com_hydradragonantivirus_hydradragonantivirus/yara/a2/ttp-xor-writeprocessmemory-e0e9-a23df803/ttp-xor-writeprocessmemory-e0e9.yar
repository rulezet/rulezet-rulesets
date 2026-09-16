rule TTP_XOR_WriteProcessMemory_e0e9 {
  strings:
    $key_e0e9 = { b7 9b [2] 85 b9 [2] 83 8c [2] ad 8c [2] 92 90 }

  condition:
    any of them
}