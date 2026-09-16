rule TTP_XOR_WriteProcessMemory_2d15 {
  strings:
    $key_2d15 = { 7a 67 [2] 48 45 [2] 4e 70 [2] 60 70 [2] 5f 6c }

  condition:
    any of them
}