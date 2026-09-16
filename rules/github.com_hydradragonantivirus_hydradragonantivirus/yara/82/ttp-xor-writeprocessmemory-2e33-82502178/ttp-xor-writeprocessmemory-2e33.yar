rule TTP_XOR_WriteProcessMemory_2e33 {
  strings:
    $key_2e33 = { 79 41 [2] 4b 63 [2] 4d 56 [2] 63 56 [2] 5c 4a }

  condition:
    any of them
}