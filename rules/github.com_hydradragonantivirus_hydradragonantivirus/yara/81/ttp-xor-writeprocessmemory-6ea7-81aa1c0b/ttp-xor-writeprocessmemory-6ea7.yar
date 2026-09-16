rule TTP_XOR_WriteProcessMemory_6ea7 {
  strings:
    $key_6ea7 = { 39 d5 [2] 0b f7 [2] 0d c2 [2] 23 c2 [2] 1c de }

  condition:
    any of them
}