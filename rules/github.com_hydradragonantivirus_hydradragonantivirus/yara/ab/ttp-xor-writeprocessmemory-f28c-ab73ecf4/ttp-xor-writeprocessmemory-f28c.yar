rule TTP_XOR_WriteProcessMemory_f28c {
  strings:
    $key_f28c = { a5 fe [2] 97 dc [2] 91 e9 [2] bf e9 [2] 80 f5 }

  condition:
    any of them
}