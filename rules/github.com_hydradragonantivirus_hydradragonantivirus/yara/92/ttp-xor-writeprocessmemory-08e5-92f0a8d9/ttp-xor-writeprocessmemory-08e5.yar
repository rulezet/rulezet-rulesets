rule TTP_XOR_WriteProcessMemory_08e5 {
  strings:
    $key_08e5 = { 5f 97 [2] 6d b5 [2] 6b 80 [2] 45 80 [2] 7a 9c }

  condition:
    any of them
}