rule TTP_XOR_WriteProcessMemory_564a {
  strings:
    $key_564a = { 01 38 [2] 33 1a [2] 35 2f [2] 1b 2f [2] 24 33 }

  condition:
    any of them
}