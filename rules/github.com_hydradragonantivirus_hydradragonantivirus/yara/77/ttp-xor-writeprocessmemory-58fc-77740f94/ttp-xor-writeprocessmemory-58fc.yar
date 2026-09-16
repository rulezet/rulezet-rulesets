rule TTP_XOR_WriteProcessMemory_58fc {
  strings:
    $key_58fc = { 0f 8e [2] 3d ac [2] 3b 99 [2] 15 99 [2] 2a 85 }

  condition:
    any of them
}