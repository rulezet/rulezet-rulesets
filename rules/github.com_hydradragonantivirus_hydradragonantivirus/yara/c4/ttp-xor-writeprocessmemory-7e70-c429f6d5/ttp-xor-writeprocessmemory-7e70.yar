rule TTP_XOR_WriteProcessMemory_7e70 {
  strings:
    $key_7e70 = { 29 02 [2] 1b 20 [2] 1d 15 [2] 33 15 [2] 0c 09 }

  condition:
    any of them
}