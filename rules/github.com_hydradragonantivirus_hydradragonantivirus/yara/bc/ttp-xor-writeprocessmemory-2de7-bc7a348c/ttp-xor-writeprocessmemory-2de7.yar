rule TTP_XOR_WriteProcessMemory_2de7 {
  strings:
    $key_2de7 = { 7a 95 [2] 48 b7 [2] 4e 82 [2] 60 82 [2] 5f 9e }

  condition:
    any of them
}