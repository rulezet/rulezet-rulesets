rule TTP_XOR_WriteProcessMemory_5f4a {
  strings:
    $key_5f4a = { 08 38 [2] 3a 1a [2] 3c 2f [2] 12 2f [2] 2d 33 }

  condition:
    any of them
}