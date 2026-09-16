rule TTP_XOR_WriteProcessMemory_e16f {
  strings:
    $key_e16f = { b6 1d [2] 84 3f [2] 82 0a [2] ac 0a [2] 93 16 }

  condition:
    any of them
}