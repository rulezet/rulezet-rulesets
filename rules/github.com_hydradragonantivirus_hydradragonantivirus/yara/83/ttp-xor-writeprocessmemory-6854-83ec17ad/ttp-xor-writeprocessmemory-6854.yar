rule TTP_XOR_WriteProcessMemory_6854 {
  strings:
    $key_6854 = { 3f 26 [2] 0d 04 [2] 0b 31 [2] 25 31 [2] 1a 2d }

  condition:
    any of them
}