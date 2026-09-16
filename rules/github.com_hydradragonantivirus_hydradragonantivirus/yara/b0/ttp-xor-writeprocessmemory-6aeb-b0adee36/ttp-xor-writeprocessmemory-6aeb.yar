rule TTP_XOR_WriteProcessMemory_6aeb {
  strings:
    $key_6aeb = { 3d 99 [2] 0f bb [2] 09 8e [2] 27 8e [2] 18 92 }

  condition:
    any of them
}