rule TTP_XOR_WriteProcessMemory_384a {
  strings:
    $key_384a = { 6f 38 [2] 5d 1a [2] 5b 2f [2] 75 2f [2] 4a 33 }

  condition:
    any of them
}