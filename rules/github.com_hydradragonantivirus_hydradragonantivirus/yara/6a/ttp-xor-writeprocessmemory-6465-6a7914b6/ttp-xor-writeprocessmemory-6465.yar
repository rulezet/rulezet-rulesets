rule TTP_XOR_WriteProcessMemory_6465 {
  strings:
    $key_6465 = { 33 17 [2] 01 35 [2] 07 00 [2] 29 00 [2] 16 1c }

  condition:
    any of them
}