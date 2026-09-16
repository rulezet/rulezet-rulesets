rule TTP_XOR_WriteProcessMemory_2575 {
  strings:
    $key_2575 = { 72 07 [2] 40 25 [2] 46 10 [2] 68 10 [2] 57 0c }

  condition:
    any of them
}