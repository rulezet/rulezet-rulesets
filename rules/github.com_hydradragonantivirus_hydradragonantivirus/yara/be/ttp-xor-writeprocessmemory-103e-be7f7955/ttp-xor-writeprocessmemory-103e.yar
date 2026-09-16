rule TTP_XOR_WriteProcessMemory_103e {
  strings:
    $key_103e = { 47 4c [2] 75 6e [2] 73 5b [2] 5d 5b [2] 62 47 }

  condition:
    any of them
}