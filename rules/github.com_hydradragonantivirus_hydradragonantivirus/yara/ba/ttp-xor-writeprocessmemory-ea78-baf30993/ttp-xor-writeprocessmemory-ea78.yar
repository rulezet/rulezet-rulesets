rule TTP_XOR_WriteProcessMemory_ea78 {
  strings:
    $key_ea78 = { bd 0a [2] 8f 28 [2] 89 1d [2] a7 1d [2] 98 01 }

  condition:
    any of them
}