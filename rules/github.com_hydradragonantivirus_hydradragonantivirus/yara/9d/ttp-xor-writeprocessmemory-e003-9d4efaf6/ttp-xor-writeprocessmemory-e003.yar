rule TTP_XOR_WriteProcessMemory_e003 {
  strings:
    $key_e003 = { b7 71 [2] 85 53 [2] 83 66 [2] ad 66 [2] 92 7a }

  condition:
    any of them
}