rule TTP_XOR_WriteProcessMemory_ea0f {
  strings:
    $key_ea0f = { bd 7d [2] 8f 5f [2] 89 6a [2] a7 6a [2] 98 76 }

  condition:
    any of them
}