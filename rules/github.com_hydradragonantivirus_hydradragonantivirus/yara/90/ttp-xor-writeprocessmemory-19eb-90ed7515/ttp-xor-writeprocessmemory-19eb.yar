rule TTP_XOR_WriteProcessMemory_19eb {
  strings:
    $key_19eb = { 4e 99 [2] 7c bb [2] 7a 8e [2] 54 8e [2] 6b 92 }

  condition:
    any of them
}