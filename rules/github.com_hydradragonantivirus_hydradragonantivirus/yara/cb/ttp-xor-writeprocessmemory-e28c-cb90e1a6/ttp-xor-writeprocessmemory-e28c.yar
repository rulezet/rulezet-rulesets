rule TTP_XOR_WriteProcessMemory_e28c {
  strings:
    $key_e28c = { b5 fe [2] 87 dc [2] 81 e9 [2] af e9 [2] 90 f5 }

  condition:
    any of them
}