rule TTP_XOR_WriteProcessMemory_e000 {
  strings:
    $key_e000 = { b7 72 [2] 85 50 [2] 83 65 [2] ad 65 [2] 92 79 }

  condition:
    any of them
}