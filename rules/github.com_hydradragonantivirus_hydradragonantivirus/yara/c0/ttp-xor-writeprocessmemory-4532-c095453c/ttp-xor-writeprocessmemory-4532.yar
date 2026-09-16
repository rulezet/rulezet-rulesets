rule TTP_XOR_WriteProcessMemory_4532 {
  strings:
    $key_4532 = { 12 40 [2] 20 62 [2] 26 57 [2] 08 57 [2] 37 4b }

  condition:
    any of them
}