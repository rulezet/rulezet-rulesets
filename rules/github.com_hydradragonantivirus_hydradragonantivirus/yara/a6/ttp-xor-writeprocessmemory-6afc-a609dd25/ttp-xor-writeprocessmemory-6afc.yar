rule TTP_XOR_WriteProcessMemory_6afc {
  strings:
    $key_6afc = { 3d 8e [2] 0f ac [2] 09 99 [2] 27 99 [2] 18 85 }

  condition:
    any of them
}