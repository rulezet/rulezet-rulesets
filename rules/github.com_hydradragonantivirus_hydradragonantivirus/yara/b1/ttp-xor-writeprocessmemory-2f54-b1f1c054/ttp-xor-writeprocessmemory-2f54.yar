rule TTP_XOR_WriteProcessMemory_2f54 {
  strings:
    $key_2f54 = { 78 26 [2] 4a 04 [2] 4c 31 [2] 62 31 [2] 5d 2d }

  condition:
    any of them
}