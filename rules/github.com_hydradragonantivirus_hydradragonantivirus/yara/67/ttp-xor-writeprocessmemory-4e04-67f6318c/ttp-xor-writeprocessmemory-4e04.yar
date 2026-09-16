rule TTP_XOR_WriteProcessMemory_4e04 {
  strings:
    $key_4e04 = { 19 76 [2] 2b 54 [2] 2d 61 [2] 03 61 [2] 3c 7d }

  condition:
    any of them
}