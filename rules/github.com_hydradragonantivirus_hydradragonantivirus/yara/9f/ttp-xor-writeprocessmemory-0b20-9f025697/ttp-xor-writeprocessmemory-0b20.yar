rule TTP_XOR_WriteProcessMemory_0b20 {
  strings:
    $key_0b20 = { 5c 52 [2] 6e 70 [2] 68 45 [2] 46 45 [2] 79 59 }

  condition:
    any of them
}