rule TTP_XOR_WriteProcessMemory_1605 {
  strings:
    $key_1605 = { 41 77 [2] 73 55 [2] 75 60 [2] 5b 60 [2] 64 7c }

  condition:
    any of them
}