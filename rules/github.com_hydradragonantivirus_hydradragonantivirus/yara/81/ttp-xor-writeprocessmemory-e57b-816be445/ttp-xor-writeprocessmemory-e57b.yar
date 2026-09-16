rule TTP_XOR_WriteProcessMemory_e57b {
  strings:
    $key_e57b = { b2 09 [2] 80 2b [2] 86 1e [2] a8 1e [2] 97 02 }

  condition:
    any of them
}