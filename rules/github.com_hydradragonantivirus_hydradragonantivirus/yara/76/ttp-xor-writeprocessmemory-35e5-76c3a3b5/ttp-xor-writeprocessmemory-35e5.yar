rule TTP_XOR_WriteProcessMemory_35e5 {
  strings:
    $key_35e5 = { 62 97 [2] 50 b5 [2] 56 80 [2] 78 80 [2] 47 9c }

  condition:
    any of them
}