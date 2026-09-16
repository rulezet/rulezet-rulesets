rule TTP_XOR_WriteProcessMemory_c92e {
  strings:
    $key_c92e = { 9e 5c [2] ac 7e [2] aa 4b [2] 84 4b [2] bb 57 }

  condition:
    any of them
}