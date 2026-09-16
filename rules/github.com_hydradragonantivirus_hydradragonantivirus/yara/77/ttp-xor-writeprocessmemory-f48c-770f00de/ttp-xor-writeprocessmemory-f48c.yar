rule TTP_XOR_WriteProcessMemory_f48c {
  strings:
    $key_f48c = { a3 fe [2] 91 dc [2] 97 e9 [2] b9 e9 [2] 86 f5 }

  condition:
    any of them
}