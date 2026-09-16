rule TTP_XOR_WriteProcessMemory_5453 {
  strings:
    $key_5453 = { 03 21 [2] 31 03 [2] 37 36 [2] 19 36 [2] 26 2a }

  condition:
    any of them
}