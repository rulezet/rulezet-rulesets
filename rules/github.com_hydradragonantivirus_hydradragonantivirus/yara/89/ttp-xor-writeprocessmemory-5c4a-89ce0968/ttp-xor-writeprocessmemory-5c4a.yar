rule TTP_XOR_WriteProcessMemory_5c4a {
  strings:
    $key_5c4a = { 0b 38 [2] 39 1a [2] 3f 2f [2] 11 2f [2] 2e 33 }

  condition:
    any of them
}