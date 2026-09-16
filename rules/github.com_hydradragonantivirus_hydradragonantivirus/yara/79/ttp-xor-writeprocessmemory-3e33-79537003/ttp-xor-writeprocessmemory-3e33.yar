rule TTP_XOR_WriteProcessMemory_3e33 {
  strings:
    $key_3e33 = { 69 41 [2] 5b 63 [2] 5d 56 [2] 73 56 [2] 4c 4a }

  condition:
    any of them
}