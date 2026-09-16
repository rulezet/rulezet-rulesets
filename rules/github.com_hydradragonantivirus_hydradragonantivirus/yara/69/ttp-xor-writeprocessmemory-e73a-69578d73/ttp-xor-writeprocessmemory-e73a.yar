rule TTP_XOR_WriteProcessMemory_e73a {
  strings:
    $key_e73a = { b0 48 [2] 82 6a [2] 84 5f [2] aa 5f [2] 95 43 }

  condition:
    any of them
}