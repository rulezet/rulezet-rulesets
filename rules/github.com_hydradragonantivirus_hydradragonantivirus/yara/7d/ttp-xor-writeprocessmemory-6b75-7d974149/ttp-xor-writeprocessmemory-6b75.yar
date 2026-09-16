rule TTP_XOR_WriteProcessMemory_6b75 {
  strings:
    $key_6b75 = { 3c 07 [2] 0e 25 [2] 08 10 [2] 26 10 [2] 19 0c }

  condition:
    any of them
}