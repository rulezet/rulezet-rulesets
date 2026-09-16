rule TTP_XOR_WriteProcessMemory_e12b {
  strings:
    $key_e12b = { b6 59 [2] 84 7b [2] 82 4e [2] ac 4e [2] 93 52 }

  condition:
    any of them
}