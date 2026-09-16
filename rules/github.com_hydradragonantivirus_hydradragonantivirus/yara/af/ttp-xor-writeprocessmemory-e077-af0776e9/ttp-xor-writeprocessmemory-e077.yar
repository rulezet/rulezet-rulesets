rule TTP_XOR_WriteProcessMemory_e077 {
  strings:
    $key_e077 = { b7 05 [2] 85 27 [2] 83 12 [2] ad 12 [2] 92 0e }

  condition:
    any of them
}