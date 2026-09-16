rule TTP_XOR_WriteProcessMemory_1775 {
  strings:
    $key_1775 = { 40 07 [2] 72 25 [2] 74 10 [2] 5a 10 [2] 65 0c }

  condition:
    any of them
}