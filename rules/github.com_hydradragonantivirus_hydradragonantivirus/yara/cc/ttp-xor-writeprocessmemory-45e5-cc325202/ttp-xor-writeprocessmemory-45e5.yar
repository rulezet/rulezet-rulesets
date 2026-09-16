rule TTP_XOR_WriteProcessMemory_45e5 {
  strings:
    $key_45e5 = { 12 97 [2] 20 b5 [2] 26 80 [2] 08 80 [2] 37 9c }

  condition:
    any of them
}