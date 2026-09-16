rule TTP_XOR_WriteProcessMemory_4644 {
  strings:
    $key_4644 = { 11 36 [2] 23 14 [2] 25 21 [2] 0b 21 [2] 34 3d }

  condition:
    any of them
}