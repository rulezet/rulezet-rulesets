rule TTP_XOR_WriteProcessMemory_2705 {
  strings:
    $key_2705 = { 70 77 [2] 42 55 [2] 44 60 [2] 6a 60 [2] 55 7c }

  condition:
    any of them
}