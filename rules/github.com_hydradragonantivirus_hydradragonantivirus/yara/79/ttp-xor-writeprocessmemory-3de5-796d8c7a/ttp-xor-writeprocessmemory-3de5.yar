rule TTP_XOR_WriteProcessMemory_3de5 {
  strings:
    $key_3de5 = { 6a 97 [2] 58 b5 [2] 5e 80 [2] 70 80 [2] 4f 9c }

  condition:
    any of them
}