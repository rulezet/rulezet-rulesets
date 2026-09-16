rule TTP_XOR_WriteProcessMemory_734a {
  strings:
    $key_734a = { 24 38 [2] 16 1a [2] 10 2f [2] 3e 2f [2] 01 33 }

  condition:
    any of them
}