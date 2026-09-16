rule TTP_XOR_WriteProcessMemory_2e52 {
  strings:
    $key_2e52 = { 79 20 [2] 4b 02 [2] 4d 37 [2] 63 37 [2] 5c 2b }

  condition:
    any of them
}