rule TTP_XOR_WriteProcessMemory_e17e {
  strings:
    $key_e17e = { b6 0c [2] 84 2e [2] 82 1b [2] ac 1b [2] 93 07 }

  condition:
    any of them
}