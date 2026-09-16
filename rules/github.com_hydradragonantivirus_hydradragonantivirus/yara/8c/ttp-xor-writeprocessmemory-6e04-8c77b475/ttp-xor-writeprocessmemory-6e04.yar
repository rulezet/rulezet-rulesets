rule TTP_XOR_WriteProcessMemory_6e04 {
  strings:
    $key_6e04 = { 39 76 [2] 0b 54 [2] 0d 61 [2] 23 61 [2] 1c 7d }

  condition:
    any of them
}