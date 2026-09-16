rule TTP_XOR_WriteProcessMemory_4535 {
  strings:
    $key_4535 = { 12 47 [2] 20 65 [2] 26 50 [2] 08 50 [2] 37 4c }

  condition:
    any of them
}