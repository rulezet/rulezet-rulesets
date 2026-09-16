rule TTP_XOR_WriteProcessMemory_55e5 {
  strings:
    $key_55e5 = { 02 97 [2] 30 b5 [2] 36 80 [2] 18 80 [2] 27 9c }

  condition:
    any of them
}