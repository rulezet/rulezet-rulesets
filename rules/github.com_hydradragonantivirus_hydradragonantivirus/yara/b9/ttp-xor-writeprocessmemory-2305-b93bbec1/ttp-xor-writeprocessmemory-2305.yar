rule TTP_XOR_WriteProcessMemory_2305 {
  strings:
    $key_2305 = { 74 77 [2] 46 55 [2] 40 60 [2] 6e 60 [2] 51 7c }

  condition:
    any of them
}