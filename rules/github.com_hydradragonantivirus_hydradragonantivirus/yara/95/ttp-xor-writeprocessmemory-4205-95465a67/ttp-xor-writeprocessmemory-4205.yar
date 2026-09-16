rule TTP_XOR_WriteProcessMemory_4205 {
  strings:
    $key_4205 = { 15 77 [2] 27 55 [2] 21 60 [2] 0f 60 [2] 30 7c }

  condition:
    any of them
}