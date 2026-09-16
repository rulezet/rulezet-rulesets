rule TTP_XOR_WriteProcessMemory_5ff2 {
  strings:
    $key_5ff2 = { 08 80 [2] 3a a2 [2] 3c 97 [2] 12 97 [2] 2d 8b }

  condition:
    any of them
}