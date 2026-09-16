rule TTP_XOR_WriteProcessMemory_7aeb {
  strings:
    $key_7aeb = { 2d 99 [2] 1f bb [2] 19 8e [2] 37 8e [2] 08 92 }

  condition:
    any of them
}