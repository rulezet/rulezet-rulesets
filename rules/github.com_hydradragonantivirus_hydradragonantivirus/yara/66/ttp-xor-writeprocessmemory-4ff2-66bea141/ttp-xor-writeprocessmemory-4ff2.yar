rule TTP_XOR_WriteProcessMemory_4ff2 {
  strings:
    $key_4ff2 = { 18 80 [2] 2a a2 [2] 2c 97 [2] 02 97 [2] 3d 8b }

  condition:
    any of them
}