rule TTP_XOR_WriteProcessMemory_e70a {
  strings:
    $key_e70a = { b0 78 [2] 82 5a [2] 84 6f [2] aa 6f [2] 95 73 }

  condition:
    any of them
}