rule TTP_XOR_WriteProcessMemory_224a {
  strings:
    $key_224a = { 75 38 [2] 47 1a [2] 41 2f [2] 6f 2f [2] 50 33 }

  condition:
    any of them
}