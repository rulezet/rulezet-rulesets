rule TTP_XOR_WriteProcessMemory_6ce5 {
  strings:
    $key_6ce5 = { 3b 97 [2] 09 b5 [2] 0f 80 [2] 21 80 [2] 1e 9c }

  condition:
    any of them
}