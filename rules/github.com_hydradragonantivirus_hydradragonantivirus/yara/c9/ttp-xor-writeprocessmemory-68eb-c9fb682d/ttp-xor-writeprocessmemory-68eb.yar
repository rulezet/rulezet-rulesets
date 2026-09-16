rule TTP_XOR_WriteProcessMemory_68eb {
  strings:
    $key_68eb = { 3f 99 [2] 0d bb [2] 0b 8e [2] 25 8e [2] 1a 92 }

  condition:
    any of them
}