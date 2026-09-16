rule TTP_XOR_WriteProcessMemory_0b02 {
  strings:
    $key_0b02 = { 5c 70 [2] 6e 52 [2] 68 67 [2] 46 67 [2] 79 7b }

  condition:
    any of them
}