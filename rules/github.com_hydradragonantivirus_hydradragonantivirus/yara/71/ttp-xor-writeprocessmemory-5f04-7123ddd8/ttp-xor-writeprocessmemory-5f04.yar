rule TTP_XOR_WriteProcessMemory_5f04 {
  strings:
    $key_5f04 = { 08 76 [2] 3a 54 [2] 3c 61 [2] 12 61 [2] 2d 7d }

  condition:
    any of them
}