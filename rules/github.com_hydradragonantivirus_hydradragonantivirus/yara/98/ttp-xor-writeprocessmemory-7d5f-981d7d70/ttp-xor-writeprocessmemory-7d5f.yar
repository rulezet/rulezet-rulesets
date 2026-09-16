rule TTP_XOR_WriteProcessMemory_7d5f {
  strings:
    $key_7d5f = { 2a 2d [2] 18 0f [2] 1e 3a [2] 30 3a [2] 0f 26 }

  condition:
    any of them
}