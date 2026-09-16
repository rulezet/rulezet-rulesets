rule TTP_XOR_WriteProcessMemory_e030 {
  strings:
    $key_e030 = { b7 42 [2] 85 60 [2] 83 55 [2] ad 55 [2] 92 49 }

  condition:
    any of them
}