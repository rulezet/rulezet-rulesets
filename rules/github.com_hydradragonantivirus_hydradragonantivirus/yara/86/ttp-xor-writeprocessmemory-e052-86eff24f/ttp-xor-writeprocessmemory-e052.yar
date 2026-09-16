rule TTP_XOR_WriteProcessMemory_e052 {
  strings:
    $key_e052 = { b7 20 [2] 85 02 [2] 83 37 [2] ad 37 [2] 92 2b }

  condition:
    any of them
}