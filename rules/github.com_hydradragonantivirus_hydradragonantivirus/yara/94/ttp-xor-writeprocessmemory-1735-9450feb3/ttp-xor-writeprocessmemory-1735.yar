rule TTP_XOR_WriteProcessMemory_1735 {
  strings:
    $key_1735 = { 40 47 [2] 72 65 [2] 74 50 [2] 5a 50 [2] 65 4c }

  condition:
    any of them
}