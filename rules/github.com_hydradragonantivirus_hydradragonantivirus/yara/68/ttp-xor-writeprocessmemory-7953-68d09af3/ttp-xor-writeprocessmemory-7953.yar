rule TTP_XOR_WriteProcessMemory_7953 {
  strings:
    $key_7953 = { 2e 21 [2] 1c 03 [2] 1a 36 [2] 34 36 [2] 0b 2a }

  condition:
    any of them
}