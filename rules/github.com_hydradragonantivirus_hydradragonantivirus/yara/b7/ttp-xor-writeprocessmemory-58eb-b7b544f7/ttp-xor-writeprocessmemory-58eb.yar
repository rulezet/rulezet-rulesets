rule TTP_XOR_WriteProcessMemory_58eb {
  strings:
    $key_58eb = { 0f 99 [2] 3d bb [2] 3b 8e [2] 15 8e [2] 2a 92 }

  condition:
    any of them
}