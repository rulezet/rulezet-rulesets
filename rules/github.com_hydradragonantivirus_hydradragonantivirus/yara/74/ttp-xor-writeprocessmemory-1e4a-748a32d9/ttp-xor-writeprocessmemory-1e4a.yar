rule TTP_XOR_WriteProcessMemory_1e4a {
  strings:
    $key_1e4a = { 49 38 [2] 7b 1a [2] 7d 2f [2] 53 2f [2] 6c 33 }

  condition:
    any of them
}