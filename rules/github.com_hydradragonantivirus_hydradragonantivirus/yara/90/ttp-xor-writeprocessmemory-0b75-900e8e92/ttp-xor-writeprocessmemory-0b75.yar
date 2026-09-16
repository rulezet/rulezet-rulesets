rule TTP_XOR_WriteProcessMemory_0b75 {
  strings:
    $key_0b75 = { 5c 07 [2] 6e 25 [2] 68 10 [2] 46 10 [2] 79 0c }

  condition:
    any of them
}