rule TTP_XOR_WriteProcessMemory_4ea7 {
  strings:
    $key_4ea7 = { 19 d5 [2] 2b f7 [2] 2d c2 [2] 03 c2 [2] 3c de }

  condition:
    any of them
}