rule TTP_XOR_WriteProcessMemory_e9eb {
  strings:
    $key_e9eb = { be 99 [2] 8c bb [2] 8a 8e [2] a4 8e [2] 9b 92 }

  condition:
    any of them
}