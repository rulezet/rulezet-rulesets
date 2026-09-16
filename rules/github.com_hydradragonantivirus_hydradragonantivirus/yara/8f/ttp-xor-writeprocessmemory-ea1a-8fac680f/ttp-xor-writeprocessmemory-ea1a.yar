rule TTP_XOR_WriteProcessMemory_ea1a {
  strings:
    $key_ea1a = { bd 68 [2] 8f 4a [2] 89 7f [2] a7 7f [2] 98 63 }

  condition:
    any of them
}