rule TTP_XOR_WriteProcessMemory_6445 {
  strings:
    $key_6445 = { 33 37 [2] 01 15 [2] 07 20 [2] 29 20 [2] 16 3c }

  condition:
    any of them
}