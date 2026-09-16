rule TTP_XOR_WriteProcessMemory_5de5 {
  strings:
    $key_5de5 = { 0a 97 [2] 38 b5 [2] 3e 80 [2] 10 80 [2] 2f 9c }

  condition:
    any of them
}