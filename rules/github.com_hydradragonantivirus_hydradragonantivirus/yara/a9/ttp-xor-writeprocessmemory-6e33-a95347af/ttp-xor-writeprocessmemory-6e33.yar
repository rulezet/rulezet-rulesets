rule TTP_XOR_WriteProcessMemory_6e33 {
  strings:
    $key_6e33 = { 39 41 [2] 0b 63 [2] 0d 56 [2] 23 56 [2] 1c 4a }

  condition:
    any of them
}