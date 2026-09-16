rule TTP_XOR_WriteProcessMemory_e04a {
  strings:
    $key_e04a = { b7 38 [2] 85 1a [2] 83 2f [2] ad 2f [2] 92 33 }

  condition:
    any of them
}