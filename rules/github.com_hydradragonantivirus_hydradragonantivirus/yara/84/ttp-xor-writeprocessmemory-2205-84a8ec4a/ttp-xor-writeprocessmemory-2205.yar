rule TTP_XOR_WriteProcessMemory_2205 {
  strings:
    $key_2205 = { 75 77 [2] 47 55 [2] 41 60 [2] 6f 60 [2] 50 7c }

  condition:
    any of them
}