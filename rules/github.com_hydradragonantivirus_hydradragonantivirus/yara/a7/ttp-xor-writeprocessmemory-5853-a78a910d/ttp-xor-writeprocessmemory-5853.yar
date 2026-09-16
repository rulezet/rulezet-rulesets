rule TTP_XOR_WriteProcessMemory_5853 {
  strings:
    $key_5853 = { 0f 21 [2] 3d 03 [2] 3b 36 [2] 15 36 [2] 2a 2a }

  condition:
    any of them
}