rule TTP_XOR_WriteProcessMemory_c94e {
  strings:
    $key_c94e = { 9e 3c [2] ac 1e [2] aa 2b [2] 84 2b [2] bb 37 }

  condition:
    any of them
}