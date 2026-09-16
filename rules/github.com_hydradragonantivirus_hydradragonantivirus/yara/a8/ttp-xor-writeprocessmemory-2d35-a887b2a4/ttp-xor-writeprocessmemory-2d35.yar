rule TTP_XOR_WriteProcessMemory_2d35 {
  strings:
    $key_2d35 = { 7a 47 [2] 48 65 [2] 4e 50 [2] 60 50 [2] 5f 4c }

  condition:
    any of them
}