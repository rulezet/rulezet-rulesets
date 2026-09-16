rule TTP_XOR_WriteProcessMemory_7971 {
  strings:
    $key_7971 = { 2e 03 [2] 1c 21 [2] 1a 14 [2] 34 14 [2] 0b 08 }

  condition:
    any of them
}