rule TTP_XOR_WriteProcessMemory_e0e3 {
  strings:
    $key_e0e3 = { b7 91 [2] 85 b3 [2] 83 86 [2] ad 86 [2] 92 9a }

  condition:
    any of them
}