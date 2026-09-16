rule TTP_XOR_WriteProcessMemory_7e33 {
  strings:
    $key_7e33 = { 29 41 [2] 1b 63 [2] 1d 56 [2] 33 56 [2] 0c 4a }

  condition:
    any of them
}