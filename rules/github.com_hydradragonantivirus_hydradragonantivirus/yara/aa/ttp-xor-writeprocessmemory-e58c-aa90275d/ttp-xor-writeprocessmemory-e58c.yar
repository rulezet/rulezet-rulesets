rule TTP_XOR_WriteProcessMemory_e58c {
  strings:
    $key_e58c = { b2 fe [2] 80 dc [2] 86 e9 [2] a8 e9 [2] 97 f5 }

  condition:
    any of them
}