rule TTP_XOR_WriteProcessMemory_ea5a {
  strings:
    $key_ea5a = { bd 28 [2] 8f 0a [2] 89 3f [2] a7 3f [2] 98 23 }

  condition:
    any of them
}