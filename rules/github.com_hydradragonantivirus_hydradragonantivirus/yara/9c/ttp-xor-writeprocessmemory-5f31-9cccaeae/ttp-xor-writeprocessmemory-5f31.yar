rule TTP_XOR_WriteProcessMemory_5f31 {
  strings:
    $key_5f31 = { 08 43 [2] 3a 61 [2] 3c 54 [2] 12 54 [2] 2d 48 }

  condition:
    any of them
}