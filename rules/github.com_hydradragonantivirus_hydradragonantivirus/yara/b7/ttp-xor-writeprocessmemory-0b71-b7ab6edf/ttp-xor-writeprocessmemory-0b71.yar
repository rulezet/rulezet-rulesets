rule TTP_XOR_WriteProcessMemory_0b71 {
  strings:
    $key_0b71 = { 5c 03 [2] 6e 21 [2] 68 14 [2] 46 14 [2] 79 08 }

  condition:
    any of them
}