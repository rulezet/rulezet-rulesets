rule TTP_XOR_WriteProcessMemory_dc8c {
  strings:
    $key_dc8c = { 8b fe [2] b9 dc [2] bf e9 [2] 91 e9 [2] ae f5 }

  condition:
    any of them
}