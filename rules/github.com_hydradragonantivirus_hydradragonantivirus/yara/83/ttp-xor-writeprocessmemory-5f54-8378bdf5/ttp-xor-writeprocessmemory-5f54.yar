rule TTP_XOR_WriteProcessMemory_5f54 {
  strings:
    $key_5f54 = { 08 26 [2] 3a 04 [2] 3c 31 [2] 12 31 [2] 2d 2d }

  condition:
    any of them
}