rule TTP_XOR_WriteProcessMemory_5aeb {
  strings:
    $key_5aeb = { 0d 99 [2] 3f bb [2] 39 8e [2] 17 8e [2] 28 92 }

  condition:
    any of them
}