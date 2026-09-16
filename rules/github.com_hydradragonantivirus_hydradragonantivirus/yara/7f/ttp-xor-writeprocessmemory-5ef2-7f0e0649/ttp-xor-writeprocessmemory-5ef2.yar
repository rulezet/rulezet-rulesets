rule TTP_XOR_WriteProcessMemory_5ef2 {
  strings:
    $key_5ef2 = { 09 80 [2] 3b a2 [2] 3d 97 [2] 13 97 [2] 2c 8b }

  condition:
    any of them
}