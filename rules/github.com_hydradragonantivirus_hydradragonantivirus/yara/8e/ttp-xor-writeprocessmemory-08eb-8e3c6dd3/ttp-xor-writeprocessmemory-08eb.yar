rule TTP_XOR_WriteProcessMemory_08eb {
  strings:
    $key_08eb = { 5f 99 [2] 6d bb [2] 6b 8e [2] 45 8e [2] 7a 92 }

  condition:
    any of them
}