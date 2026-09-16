rule TTP_XOR_WriteProcessMemory_7ea7 {
  strings:
    $key_7ea7 = { 29 d5 [2] 1b f7 [2] 1d c2 [2] 33 c2 [2] 0c de }

  condition:
    any of them
}