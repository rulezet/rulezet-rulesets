rule TTP_XOR_WriteProcessMemory_2425 {
  strings:
    $key_2425 = { 73 57 [2] 41 75 [2] 47 40 [2] 69 40 [2] 56 5c }

  condition:
    any of them
}