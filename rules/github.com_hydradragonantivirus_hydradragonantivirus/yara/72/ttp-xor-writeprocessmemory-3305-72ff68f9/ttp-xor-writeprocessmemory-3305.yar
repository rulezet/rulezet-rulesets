rule TTP_XOR_WriteProcessMemory_3305 {
  strings:
    $key_3305 = { 64 77 [2] 56 55 [2] 50 60 [2] 7e 60 [2] 41 7c }

  condition:
    any of them
}