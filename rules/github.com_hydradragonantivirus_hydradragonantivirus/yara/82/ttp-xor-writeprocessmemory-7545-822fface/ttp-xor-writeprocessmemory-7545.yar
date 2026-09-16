rule TTP_XOR_WriteProcessMemory_7545 {
  strings:
    $key_7545 = { 22 37 [2] 10 15 [2] 16 20 [2] 38 20 [2] 07 3c }

  condition:
    any of them
}