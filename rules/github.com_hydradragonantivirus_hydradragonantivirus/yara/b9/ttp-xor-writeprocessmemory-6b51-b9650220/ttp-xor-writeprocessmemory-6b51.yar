rule TTP_XOR_WriteProcessMemory_6b51 {
  strings:
    $key_6b51 = { 3c 23 [2] 0e 01 [2] 08 34 [2] 26 34 [2] 19 28 }

  condition:
    any of them
}