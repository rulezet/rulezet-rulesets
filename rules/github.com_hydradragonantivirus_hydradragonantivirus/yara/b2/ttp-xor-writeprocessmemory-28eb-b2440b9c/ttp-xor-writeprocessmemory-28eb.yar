rule TTP_XOR_WriteProcessMemory_28eb {
  strings:
    $key_28eb = { 7f 99 [2] 4d bb [2] 4b 8e [2] 65 8e [2] 5a 92 }

  condition:
    any of them
}