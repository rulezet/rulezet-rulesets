rule TTP_XOR_WriteProcessMemory_6e4a {
  strings:
    $key_6e4a = { 39 38 [2] 0b 1a [2] 0d 2f [2] 23 2f [2] 1c 33 }

  condition:
    any of them
}