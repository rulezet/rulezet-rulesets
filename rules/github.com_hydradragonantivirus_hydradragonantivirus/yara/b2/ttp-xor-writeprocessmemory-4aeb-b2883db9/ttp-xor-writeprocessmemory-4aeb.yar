rule TTP_XOR_WriteProcessMemory_4aeb {
  strings:
    $key_4aeb = { 1d 99 [2] 2f bb [2] 29 8e [2] 07 8e [2] 38 92 }

  condition:
    any of them
}