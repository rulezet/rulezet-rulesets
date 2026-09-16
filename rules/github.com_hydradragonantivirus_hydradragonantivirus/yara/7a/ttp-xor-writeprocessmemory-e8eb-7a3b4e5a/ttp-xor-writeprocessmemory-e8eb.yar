rule TTP_XOR_WriteProcessMemory_e8eb {
  strings:
    $key_e8eb = { bf 99 [2] 8d bb [2] 8b 8e [2] a5 8e [2] 9a 92 }

  condition:
    any of them
}