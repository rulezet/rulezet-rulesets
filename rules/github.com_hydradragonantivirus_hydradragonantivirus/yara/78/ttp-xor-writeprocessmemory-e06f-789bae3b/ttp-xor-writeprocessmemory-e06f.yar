rule TTP_XOR_WriteProcessMemory_e06f {
  strings:
    $key_e06f = { b7 1d [2] 85 3f [2] 83 0a [2] ad 0a [2] 92 16 }

  condition:
    any of them
}