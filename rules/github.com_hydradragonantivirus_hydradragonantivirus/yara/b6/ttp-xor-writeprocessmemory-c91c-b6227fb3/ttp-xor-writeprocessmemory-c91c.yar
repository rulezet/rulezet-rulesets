rule TTP_XOR_WriteProcessMemory_c91c {
  strings:
    $key_c91c = { 9e 6e [2] ac 4c [2] aa 79 [2] 84 79 [2] bb 65 }

  condition:
    any of them
}