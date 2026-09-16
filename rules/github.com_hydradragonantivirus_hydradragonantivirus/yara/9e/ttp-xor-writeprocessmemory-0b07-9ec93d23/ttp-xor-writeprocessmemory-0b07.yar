rule TTP_XOR_WriteProcessMemory_0b07 {
  strings:
    $key_0b07 = { 5c 75 [2] 6e 57 [2] 68 62 [2] 46 62 [2] 79 7e }

  condition:
    any of them
}