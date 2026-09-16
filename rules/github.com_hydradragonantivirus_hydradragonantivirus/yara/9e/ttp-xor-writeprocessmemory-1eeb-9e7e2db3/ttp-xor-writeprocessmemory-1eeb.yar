rule TTP_XOR_WriteProcessMemory_1eeb {
  strings:
    $key_1eeb = { 49 99 [2] 7b bb [2] 7d 8e [2] 53 8e [2] 6c 92 }

  condition:
    any of them
}