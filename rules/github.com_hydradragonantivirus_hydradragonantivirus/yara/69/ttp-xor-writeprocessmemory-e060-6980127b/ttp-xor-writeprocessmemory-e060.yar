rule TTP_XOR_WriteProcessMemory_e060 {
  strings:
    $key_e060 = { b7 12 [2] 85 30 [2] 83 05 [2] ad 05 [2] 92 19 }

  condition:
    any of them
}