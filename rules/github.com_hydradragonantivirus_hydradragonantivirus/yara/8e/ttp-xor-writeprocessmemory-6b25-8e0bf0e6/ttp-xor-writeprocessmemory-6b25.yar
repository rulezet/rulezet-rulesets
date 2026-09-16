rule TTP_XOR_WriteProcessMemory_6b25 {
  strings:
    $key_6b25 = { 3c 57 [2] 0e 75 [2] 08 40 [2] 26 40 [2] 19 5c }

  condition:
    any of them
}