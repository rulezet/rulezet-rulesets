rule TTP_XOR_WriteProcessMemory_2eeb {
  strings:
    $key_2eeb = { 79 99 [2] 4b bb [2] 4d 8e [2] 63 8e [2] 5c 92 }

  condition:
    any of them
}