rule TTP_XOR_WriteProcessMemory_41e7 {
  strings:
    $key_41e7 = { 16 95 [2] 24 b7 [2] 22 82 [2] 0c 82 [2] 33 9e }

  condition:
    any of them
}