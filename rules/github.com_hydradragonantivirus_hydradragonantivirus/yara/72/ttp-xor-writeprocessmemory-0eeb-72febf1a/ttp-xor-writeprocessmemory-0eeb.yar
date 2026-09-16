rule TTP_XOR_WriteProcessMemory_0eeb {
  strings:
    $key_0eeb = { 59 99 [2] 6b bb [2] 6d 8e [2] 43 8e [2] 7c 92 }

  condition:
    any of them
}