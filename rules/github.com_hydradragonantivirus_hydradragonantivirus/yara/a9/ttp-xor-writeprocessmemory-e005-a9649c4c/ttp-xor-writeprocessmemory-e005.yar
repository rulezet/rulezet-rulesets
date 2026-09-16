rule TTP_XOR_WriteProcessMemory_e005 {
  strings:
    $key_e005 = { b7 77 [2] 85 55 [2] 83 60 [2] ad 60 [2] 92 7c }

  condition:
    any of them
}