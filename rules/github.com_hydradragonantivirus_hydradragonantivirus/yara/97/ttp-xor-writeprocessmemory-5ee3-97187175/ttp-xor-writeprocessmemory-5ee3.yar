rule TTP_XOR_WriteProcessMemory_5ee3 {
  strings:
    $key_5ee3 = { 09 91 [2] 3b b3 [2] 3d 86 [2] 13 86 [2] 2c 9a }

  condition:
    any of them
}