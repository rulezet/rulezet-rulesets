rule TTP_XOR_WriteProcessMemory_e11b {
  strings:
    $key_e11b = { b6 69 [2] 84 4b [2] 82 7e [2] ac 7e [2] 93 62 }

  condition:
    any of them
}