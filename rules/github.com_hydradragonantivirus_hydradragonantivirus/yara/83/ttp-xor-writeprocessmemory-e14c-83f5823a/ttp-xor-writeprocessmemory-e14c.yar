rule TTP_XOR_WriteProcessMemory_e14c {
  strings:
    $key_e14c = { b6 3e [2] 84 1c [2] 82 29 [2] ac 29 [2] 93 35 }

  condition:
    any of them
}