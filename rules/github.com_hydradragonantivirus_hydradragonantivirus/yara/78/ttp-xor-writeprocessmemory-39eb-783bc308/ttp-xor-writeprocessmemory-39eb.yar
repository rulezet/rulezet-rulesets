rule TTP_XOR_WriteProcessMemory_39eb {
  strings:
    $key_39eb = { 6e 99 [2] 5c bb [2] 5a 8e [2] 74 8e [2] 4b 92 }

  condition:
    any of them
}