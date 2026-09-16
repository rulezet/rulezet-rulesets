rule TTP_XOR_WriteProcessMemory_41e5 {
  strings:
    $key_41e5 = { 16 97 [2] 24 b5 [2] 22 80 [2] 0c 80 [2] 33 9c }

  condition:
    any of them
}