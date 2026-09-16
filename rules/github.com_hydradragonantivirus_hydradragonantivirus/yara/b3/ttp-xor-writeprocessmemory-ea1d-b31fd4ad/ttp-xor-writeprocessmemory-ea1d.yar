rule TTP_XOR_WriteProcessMemory_ea1d {
  strings:
    $key_ea1d = { bd 6f [2] 8f 4d [2] 89 78 [2] a7 78 [2] 98 64 }

  condition:
    any of them
}