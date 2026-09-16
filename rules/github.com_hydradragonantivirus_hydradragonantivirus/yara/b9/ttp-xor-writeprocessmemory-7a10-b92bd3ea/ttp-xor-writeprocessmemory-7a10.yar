rule TTP_XOR_WriteProcessMemory_7a10 {
  strings:
    $key_7a10 = { 2d 62 [2] 1f 40 [2] 19 75 [2] 37 75 [2] 08 69 }

  condition:
    any of them
}