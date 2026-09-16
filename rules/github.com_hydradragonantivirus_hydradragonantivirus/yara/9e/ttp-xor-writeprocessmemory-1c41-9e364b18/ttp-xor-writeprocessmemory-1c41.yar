rule TTP_XOR_WriteProcessMemory_1c41 {
  strings:
    $key_1c41 = { 4b 33 [2] 79 11 [2] 7f 24 [2] 51 24 [2] 6e 38 }

  condition:
    any of them
}