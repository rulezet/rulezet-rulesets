rule TTP_XOR_WriteProcessMemory_4505 {
  strings:
    $key_4505 = { 12 77 [2] 20 55 [2] 26 60 [2] 08 60 [2] 37 7c }

  condition:
    any of them
}