rule TTP_XOR_WriteProcessMemory_0b65 {
  strings:
    $key_0b65 = { 5c 17 [2] 6e 35 [2] 68 00 [2] 46 00 [2] 79 1c }

  condition:
    any of them
}