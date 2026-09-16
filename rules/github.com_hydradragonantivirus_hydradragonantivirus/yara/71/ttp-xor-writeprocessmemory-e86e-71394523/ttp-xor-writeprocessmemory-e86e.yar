rule TTP_XOR_WriteProcessMemory_e86e {
  strings:
    $key_e86e = { bf 1c [2] 8d 3e [2] 8b 0b [2] a5 0b [2] 9a 17 }

  condition:
    any of them
}