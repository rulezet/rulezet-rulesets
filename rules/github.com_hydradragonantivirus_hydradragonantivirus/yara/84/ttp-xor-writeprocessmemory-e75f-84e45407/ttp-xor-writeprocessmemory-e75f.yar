rule TTP_XOR_WriteProcessMemory_e75f {
  strings:
    $key_e75f = { b0 2d [2] 82 0f [2] 84 3a [2] aa 3a [2] 95 26 }

  condition:
    any of them
}