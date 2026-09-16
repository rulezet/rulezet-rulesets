rule TTP_XOR_WriteProcessMemory_4eeb {
  strings:
    $key_4eeb = { 19 99 [2] 2b bb [2] 2d 8e [2] 03 8e [2] 3c 92 }

  condition:
    any of them
}