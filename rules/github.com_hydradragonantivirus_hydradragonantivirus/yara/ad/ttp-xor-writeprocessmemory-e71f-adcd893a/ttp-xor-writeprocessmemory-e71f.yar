rule TTP_XOR_WriteProcessMemory_e71f {
  strings:
    $key_e71f = { b0 6d [2] 82 4f [2] 84 7a [2] aa 7a [2] 95 66 }

  condition:
    any of them
}