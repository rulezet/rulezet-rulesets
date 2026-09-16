rule TTP_XOR_WriteProcessMemory_4a10 {
  strings:
    $key_4a10 = { 1d 62 [2] 2f 40 [2] 29 75 [2] 07 75 [2] 38 69 }

  condition:
    any of them
}