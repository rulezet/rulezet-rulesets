rule TTP_XOR_WriteProcessMemory_2105 {
  strings:
    $key_2105 = { 76 77 [2] 44 55 [2] 42 60 [2] 6c 60 [2] 53 7c }

  condition:
    any of them
}