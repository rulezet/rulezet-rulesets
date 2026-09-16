rule TTP_XOR_WriteProcessMemory_ea3f {
  strings:
    $key_ea3f = { bd 4d [2] 8f 6f [2] 89 5a [2] a7 5a [2] 98 46 }

  condition:
    any of them
}