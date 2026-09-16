rule TTP_XOR_WriteProcessMemory_ea48 {
  strings:
    $key_ea48 = { bd 3a [2] 8f 18 [2] 89 2d [2] a7 2d [2] 98 31 }

  condition:
    any of them
}