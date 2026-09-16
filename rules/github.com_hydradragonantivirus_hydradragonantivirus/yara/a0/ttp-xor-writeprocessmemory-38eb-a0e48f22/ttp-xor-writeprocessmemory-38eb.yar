rule TTP_XOR_WriteProcessMemory_38eb {
  strings:
    $key_38eb = { 6f 99 [2] 5d bb [2] 5b 8e [2] 75 8e [2] 4a 92 }

  condition:
    any of them
}