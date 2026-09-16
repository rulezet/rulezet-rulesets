rule TTP_XOR_WriteProcessMemory_6751 {
  strings:
    $key_6751 = { 30 23 [2] 02 01 [2] 04 34 [2] 2a 34 [2] 15 28 }

  condition:
    any of them
}