rule TTP_XOR_WriteProcessMemory_0b21 {
  strings:
    $key_0b21 = { 5c 53 [2] 6e 71 [2] 68 44 [2] 46 44 [2] 79 58 }

  condition:
    any of them
}