rule TTP_XOR_WriteProcessMemory_c9ce {
  strings:
    $key_c9ce = { 9e bc [2] ac 9e [2] aa ab [2] 84 ab [2] bb b7 }

  condition:
    any of them
}