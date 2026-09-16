rule TTP_XOR_WriteProcessMemory_2545 {
  strings:
    $key_2545 = { 72 37 [2] 40 15 [2] 46 20 [2] 68 20 [2] 57 3c }

  condition:
    any of them
}