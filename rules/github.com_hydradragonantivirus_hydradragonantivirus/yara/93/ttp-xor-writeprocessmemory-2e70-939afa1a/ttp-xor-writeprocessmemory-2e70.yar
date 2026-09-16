rule TTP_XOR_WriteProcessMemory_2e70 {
  strings:
    $key_2e70 = { 79 02 [2] 4b 20 [2] 4d 15 [2] 63 15 [2] 5c 09 }

  condition:
    any of them
}