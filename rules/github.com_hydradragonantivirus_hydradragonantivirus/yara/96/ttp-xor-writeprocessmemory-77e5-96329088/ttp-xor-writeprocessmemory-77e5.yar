rule TTP_XOR_WriteProcessMemory_77e5 {
  strings:
    $key_77e5 = { 20 97 [2] 12 b5 [2] 14 80 [2] 3a 80 [2] 05 9c }

  condition:
    any of them
}