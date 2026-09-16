rule TTP_XOR_WriteProcessMemory_084a {
  strings:
    $key_084a = { 5f 38 [2] 6d 1a [2] 6b 2f [2] 45 2f [2] 7a 33 }

  condition:
    any of them
}