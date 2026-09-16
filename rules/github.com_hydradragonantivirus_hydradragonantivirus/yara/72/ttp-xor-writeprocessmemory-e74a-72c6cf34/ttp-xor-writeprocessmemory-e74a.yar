rule TTP_XOR_WriteProcessMemory_e74a {
  strings:
    $key_e74a = { b0 38 [2] 82 1a [2] 84 2f [2] aa 2f [2] 95 33 }

  condition:
    any of them
}