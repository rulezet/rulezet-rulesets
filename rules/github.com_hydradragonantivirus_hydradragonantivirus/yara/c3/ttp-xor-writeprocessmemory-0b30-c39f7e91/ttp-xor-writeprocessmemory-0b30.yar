rule TTP_XOR_WriteProcessMemory_0b30 {
  strings:
    $key_0b30 = { 5c 42 [2] 6e 60 [2] 68 55 [2] 46 55 [2] 79 49 }

  condition:
    any of them
}