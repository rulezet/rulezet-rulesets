rule TTP_XOR_WriteProcessMemory_2e4a {
  strings:
    $key_2e4a = { 79 38 [2] 4b 1a [2] 4d 2f [2] 63 2f [2] 5c 33 }

  condition:
    any of them
}