rule TTP_XOR_WriteProcessMemory_5153 {
  strings:
    $key_5153 = { 06 21 [2] 34 03 [2] 32 36 [2] 1c 36 [2] 23 2a }

  condition:
    any of them
}