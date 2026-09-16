rule TTP_XOR_WriteProcessMemory_e72f {
  strings:
    $key_e72f = { b0 5d [2] 82 7f [2] 84 4a [2] aa 4a [2] 95 56 }

  condition:
    any of them
}