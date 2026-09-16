rule TTP_XOR_WriteProcessMemory_5653 {
  strings:
    $key_5653 = { 01 21 [2] 33 03 [2] 35 36 [2] 1b 36 [2] 24 2a }

  condition:
    any of them
}