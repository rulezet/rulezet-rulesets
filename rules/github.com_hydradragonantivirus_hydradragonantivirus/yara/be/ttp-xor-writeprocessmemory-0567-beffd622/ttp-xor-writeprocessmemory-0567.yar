rule TTP_XOR_WriteProcessMemory_0567 {
  strings:
    $key_0567 = { 52 15 [2] 60 37 [2] 66 02 [2] 48 02 [2] 77 1e }

  condition:
    any of them
}