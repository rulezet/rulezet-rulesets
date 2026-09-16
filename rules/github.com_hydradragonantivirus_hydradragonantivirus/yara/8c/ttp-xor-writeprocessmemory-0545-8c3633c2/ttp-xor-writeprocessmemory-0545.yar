rule TTP_XOR_WriteProcessMemory_0545 {
  strings:
    $key_0545 = { 52 37 [2] 60 15 [2] 66 20 [2] 48 20 [2] 77 3c }

  condition:
    any of them
}