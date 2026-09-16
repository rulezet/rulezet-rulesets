rule TTP_XOR_WriteProcessMemory_5fb9 {
  strings:
    $key_5fb9 = { 08 cb [2] 3a e9 [2] 3c dc [2] 12 dc [2] 2d c0 }

  condition:
    any of them
}