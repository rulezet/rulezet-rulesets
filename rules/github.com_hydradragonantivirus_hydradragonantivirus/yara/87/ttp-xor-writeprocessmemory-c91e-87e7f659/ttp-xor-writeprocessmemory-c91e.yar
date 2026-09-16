rule TTP_XOR_WriteProcessMemory_c91e {
  strings:
    $key_c91e = { 9e 6c [2] ac 4e [2] aa 7b [2] 84 7b [2] bb 67 }

  condition:
    any of them
}