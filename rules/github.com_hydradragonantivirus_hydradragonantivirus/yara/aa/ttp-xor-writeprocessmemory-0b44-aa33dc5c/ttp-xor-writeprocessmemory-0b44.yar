rule TTP_XOR_WriteProcessMemory_0b44 {
  strings:
    $key_0b44 = { 5c 36 [2] 6e 14 [2] 68 21 [2] 46 21 [2] 79 3d }

  condition:
    any of them
}