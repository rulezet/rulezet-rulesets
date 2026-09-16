rule TTP_XOR_WriteProcessMemory_e027 {
  strings:
    $key_e027 = { b7 55 [2] 85 77 [2] 83 42 [2] ad 42 [2] 92 5e }

  condition:
    any of them
}