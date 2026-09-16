rule TTP_XOR_WriteProcessMemory_e17b {
  strings:
    $key_e17b = { b6 09 [2] 84 2b [2] 82 1e [2] ac 1e [2] 93 02 }

  condition:
    any of them
}