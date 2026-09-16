rule TTP_XOR_WriteProcessMemory_1a10 {
  strings:
    $key_1a10 = { 4d 62 [2] 7f 40 [2] 79 75 [2] 57 75 [2] 68 69 }

  condition:
    any of them
}