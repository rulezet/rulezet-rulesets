rule TTP_XOR_WriteProcessMemory_5eeb {
  strings:
    $key_5eeb = { 09 99 [2] 3b bb [2] 3d 8e [2] 13 8e [2] 2c 92 }

  condition:
    any of them
}