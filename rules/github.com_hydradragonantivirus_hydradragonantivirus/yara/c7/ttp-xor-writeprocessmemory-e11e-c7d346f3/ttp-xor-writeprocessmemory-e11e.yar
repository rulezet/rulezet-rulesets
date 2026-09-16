rule TTP_XOR_WriteProcessMemory_e11e {
  strings:
    $key_e11e = { b6 6c [2] 84 4e [2] 82 7b [2] ac 7b [2] 93 67 }

  condition:
    any of them
}