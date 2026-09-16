rule TTP_XOR_WriteProcessMemory_7e00 {
  strings:
    $key_7e00 = { 29 72 [2] 1b 50 [2] 1d 65 [2] 33 65 [2] 0c 79 }

  condition:
    any of them
}