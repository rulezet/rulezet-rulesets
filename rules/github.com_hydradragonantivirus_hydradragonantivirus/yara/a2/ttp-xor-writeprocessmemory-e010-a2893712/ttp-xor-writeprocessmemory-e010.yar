rule TTP_XOR_WriteProcessMemory_e010 {
  strings:
    $key_e010 = { b7 62 [2] 85 40 [2] 83 75 [2] ad 75 [2] 92 69 }

  condition:
    any of them
}