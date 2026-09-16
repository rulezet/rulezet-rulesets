rule TTP_XOR_WriteProcessMemory_7186 {
  strings:
    $key_7186 = { 26 f4 [2] 14 d6 [2] 12 e3 [2] 3c e3 [2] 03 ff }

  condition:
    any of them
}