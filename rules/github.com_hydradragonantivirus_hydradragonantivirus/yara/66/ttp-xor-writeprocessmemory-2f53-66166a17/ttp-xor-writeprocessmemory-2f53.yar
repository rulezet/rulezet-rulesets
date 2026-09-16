rule TTP_XOR_WriteProcessMemory_2f53 {
  strings:
    $key_2f53 = { 78 21 [2] 4a 03 [2] 4c 36 [2] 62 36 [2] 5d 2a }

  condition:
    any of them
}