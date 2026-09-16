rule TTP_XOR_WriteProcessMemory_7eeb {
  strings:
    $key_7eeb = { 29 99 [2] 1b bb [2] 1d 8e [2] 33 8e [2] 0c 92 }

  condition:
    any of them
}