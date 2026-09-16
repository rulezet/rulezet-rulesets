rule TTP_XOR_WriteProcessMemory_c92b {
  strings:
    $key_c92b = { 9e 59 [2] ac 7b [2] aa 4e [2] 84 4e [2] bb 52 }

  condition:
    any of them
}