rule TTP_XOR_WriteProcessMemory_5620 {
  strings:
    $key_5620 = { 01 52 [2] 33 70 [2] 35 45 [2] 1b 45 [2] 24 59 }

  condition:
    any of them
}