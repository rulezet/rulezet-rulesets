rule TTP_XOR_WriteProcessMemory_0b70 {
  strings:
    $key_0b70 = { 5c 02 [2] 6e 20 [2] 68 15 [2] 46 15 [2] 79 09 }

  condition:
    any of them
}