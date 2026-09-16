rule TTP_XOR_WriteProcessMemory_e062 {
  strings:
    $key_e062 = { b7 10 [2] 85 32 [2] 83 07 [2] ad 07 [2] 92 1b }

  condition:
    any of them
}