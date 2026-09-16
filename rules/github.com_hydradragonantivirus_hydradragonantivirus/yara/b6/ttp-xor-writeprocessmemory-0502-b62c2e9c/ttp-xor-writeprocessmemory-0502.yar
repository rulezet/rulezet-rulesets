rule TTP_XOR_WriteProcessMemory_0502 {
  strings:
    $key_0502 = { 52 70 [2] 60 52 [2] 66 67 [2] 48 67 [2] 77 7b }

  condition:
    any of them
}