rule TTP_XOR_WriteProcessMemory_ea5f {
  strings:
    $key_ea5f = { bd 2d [2] 8f 0f [2] 89 3a [2] a7 3a [2] 98 26 }

  condition:
    any of them
}