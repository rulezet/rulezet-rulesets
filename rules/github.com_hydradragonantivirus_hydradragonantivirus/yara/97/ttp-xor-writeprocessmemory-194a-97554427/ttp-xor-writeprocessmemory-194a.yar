rule TTP_XOR_WriteProcessMemory_194a {
  strings:
    $key_194a = { 4e 38 [2] 7c 1a [2] 7a 2f [2] 54 2f [2] 6b 33 }

  condition:
    any of them
}