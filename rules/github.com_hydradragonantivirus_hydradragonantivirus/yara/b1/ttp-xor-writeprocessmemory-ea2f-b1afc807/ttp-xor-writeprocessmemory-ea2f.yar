rule TTP_XOR_WriteProcessMemory_ea2f {
  strings:
    $key_ea2f = { bd 5d [2] 8f 7f [2] 89 4a [2] a7 4a [2] 98 56 }

  condition:
    any of them
}