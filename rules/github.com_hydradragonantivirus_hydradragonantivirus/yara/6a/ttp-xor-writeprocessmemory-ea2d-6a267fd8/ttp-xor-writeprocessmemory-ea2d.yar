rule TTP_XOR_WriteProcessMemory_ea2d {
  strings:
    $key_ea2d = { bd 5f [2] 8f 7d [2] 89 48 [2] a7 48 [2] 98 54 }

  condition:
    any of them
}