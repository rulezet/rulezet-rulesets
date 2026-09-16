rule TTP_XOR_WriteProcessMemory_2f73 {
  strings:
    $key_2f73 = { 78 01 [2] 4a 23 [2] 4c 16 [2] 62 16 [2] 5d 0a }

  condition:
    any of them
}