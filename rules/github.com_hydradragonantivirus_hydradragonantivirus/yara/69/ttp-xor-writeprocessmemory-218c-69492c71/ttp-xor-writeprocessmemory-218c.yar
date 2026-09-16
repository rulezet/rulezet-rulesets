rule TTP_XOR_WriteProcessMemory_218c {
  strings:
    $key_218c = { 76 fe [2] 44 dc [2] 42 e9 [2] 6c e9 [2] 53 f5 }

  condition:
    any of them
}