rule TTP_XOR_WriteProcessMemory_2df5 {
  strings:
    $key_2df5 = { 7a 87 [2] 48 a5 [2] 4e 90 [2] 60 90 [2] 5f 8c }

  condition:
    any of them
}