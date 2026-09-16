rule TTP_XOR_WriteProcessMemory_2535 {
  strings:
    $key_2535 = { 72 47 [2] 40 65 [2] 46 50 [2] 68 50 [2] 57 4c }

  condition:
    any of them
}