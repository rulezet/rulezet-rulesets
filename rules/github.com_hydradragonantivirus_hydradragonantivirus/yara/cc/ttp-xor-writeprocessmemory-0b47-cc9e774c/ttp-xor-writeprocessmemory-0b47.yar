rule TTP_XOR_WriteProcessMemory_0b47 {
  strings:
    $key_0b47 = { 5c 35 [2] 6e 17 [2] 68 22 [2] 46 22 [2] 79 3e }

  condition:
    any of them
}