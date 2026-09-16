rule TTP_XOR_WriteProcessMemory_6972 {
  strings:
    $key_6972 = { 3e 00 [2] 0c 22 [2] 0a 17 [2] 24 17 [2] 1b 0b }

  condition:
    any of them
}