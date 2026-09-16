rule TTP_XOR_WriteProcessMemory_0b23 {
  strings:
    $key_0b23 = { 5c 51 [2] 6e 73 [2] 68 46 [2] 46 46 [2] 79 5a }

  condition:
    any of them
}