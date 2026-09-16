rule TTP_XOR_WriteProcessMemory_f361 {
  strings:
    $key_f361 = { a4 13 [2] 96 31 [2] 90 04 [2] be 04 [2] 81 18 }

  condition:
    any of them
}