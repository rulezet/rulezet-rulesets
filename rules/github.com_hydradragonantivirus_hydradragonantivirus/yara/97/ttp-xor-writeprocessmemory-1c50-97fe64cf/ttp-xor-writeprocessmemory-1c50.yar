rule TTP_XOR_WriteProcessMemory_1c50 {
  strings:
    $key_1c50 = { 4b 22 [2] 79 00 [2] 7f 35 [2] 51 35 [2] 6e 29 }

  condition:
    any of them
}