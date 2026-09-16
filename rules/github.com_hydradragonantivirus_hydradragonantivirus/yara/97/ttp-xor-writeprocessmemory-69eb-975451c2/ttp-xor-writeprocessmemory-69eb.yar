rule TTP_XOR_WriteProcessMemory_69eb {
  strings:
    $key_69eb = { 3e 99 [2] 0c bb [2] 0a 8e [2] 24 8e [2] 1b 92 }

  condition:
    any of them
}