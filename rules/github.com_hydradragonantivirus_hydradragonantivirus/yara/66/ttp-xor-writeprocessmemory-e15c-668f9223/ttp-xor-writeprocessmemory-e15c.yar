rule TTP_XOR_WriteProcessMemory_e15c {
  strings:
    $key_e15c = { b6 2e [2] 84 0c [2] 82 39 [2] ac 39 [2] 93 25 }

  condition:
    any of them
}