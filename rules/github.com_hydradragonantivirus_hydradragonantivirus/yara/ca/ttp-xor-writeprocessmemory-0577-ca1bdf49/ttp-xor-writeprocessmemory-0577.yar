rule TTP_XOR_WriteProcessMemory_0577 {
  strings:
    $key_0577 = { 52 05 [2] 60 27 [2] 66 12 [2] 48 12 [2] 77 0e }

  condition:
    any of them
}