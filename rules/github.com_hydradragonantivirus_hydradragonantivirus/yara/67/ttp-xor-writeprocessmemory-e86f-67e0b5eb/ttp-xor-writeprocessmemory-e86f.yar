rule TTP_XOR_WriteProcessMemory_e86f {
  strings:
    $key_e86f = { bf 1d [2] 8d 3f [2] 8b 0a [2] a5 0a [2] 9a 16 }

  condition:
    any of them
}