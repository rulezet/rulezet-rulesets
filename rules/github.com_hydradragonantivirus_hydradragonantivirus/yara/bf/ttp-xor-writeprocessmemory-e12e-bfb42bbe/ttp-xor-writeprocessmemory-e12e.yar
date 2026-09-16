rule TTP_XOR_WriteProcessMemory_e12e {
  strings:
    $key_e12e = { b6 5c [2] 84 7e [2] 82 4b [2] ac 4b [2] 93 57 }

  condition:
    any of them
}