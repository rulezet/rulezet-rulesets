rule TTP_XOR_WriteProcessMemory_eeeb {
  strings:
    $key_eeeb = { b9 99 [2] 8b bb [2] 8d 8e [2] a3 8e [2] 9c 92 }

  condition:
    any of them
}