rule TTP_XOR_WriteProcessMemory_ea6a {
  strings:
    $key_ea6a = { bd 18 [2] 8f 3a [2] 89 0f [2] a7 0f [2] 98 13 }

  condition:
    any of them
}