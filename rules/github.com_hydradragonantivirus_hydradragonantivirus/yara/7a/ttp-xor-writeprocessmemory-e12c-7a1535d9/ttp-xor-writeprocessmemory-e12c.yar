rule TTP_XOR_WriteProcessMemory_e12c {
  strings:
    $key_e12c = { b6 5e [2] 84 7c [2] 82 49 [2] ac 49 [2] 93 55 }

  condition:
    any of them
}