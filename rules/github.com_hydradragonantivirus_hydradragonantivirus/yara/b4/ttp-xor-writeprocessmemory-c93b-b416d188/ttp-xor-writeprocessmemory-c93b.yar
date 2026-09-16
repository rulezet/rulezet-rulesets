rule TTP_XOR_WriteProcessMemory_c93b {
  strings:
    $key_c93b = { 9e 49 [2] ac 6b [2] aa 5e [2] 84 5e [2] bb 42 }

  condition:
    any of them
}