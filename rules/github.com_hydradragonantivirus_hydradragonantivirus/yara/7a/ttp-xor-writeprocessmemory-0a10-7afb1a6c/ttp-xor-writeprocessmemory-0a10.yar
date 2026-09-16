rule TTP_XOR_WriteProcessMemory_0a10 {
  strings:
    $key_0a10 = { 5d 62 [2] 6f 40 [2] 69 75 [2] 47 75 [2] 78 69 }

  condition:
    any of them
}