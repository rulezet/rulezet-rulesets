rule TTP_XOR_WriteProcessMemory_7185 {
  strings:
    $key_7185 = { 26 f7 [2] 14 d5 [2] 12 e0 [2] 3c e0 [2] 03 fc }

  condition:
    any of them
}