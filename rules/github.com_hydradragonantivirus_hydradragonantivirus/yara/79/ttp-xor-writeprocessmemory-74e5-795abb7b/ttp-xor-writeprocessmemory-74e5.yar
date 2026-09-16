rule TTP_XOR_WriteProcessMemory_74e5 {
  strings:
    $key_74e5 = { 23 97 [2] 11 b5 [2] 17 80 [2] 39 80 [2] 06 9c }

  condition:
    any of them
}