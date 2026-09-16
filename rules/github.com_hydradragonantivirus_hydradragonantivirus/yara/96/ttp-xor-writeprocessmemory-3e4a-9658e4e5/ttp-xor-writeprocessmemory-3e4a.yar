rule TTP_XOR_WriteProcessMemory_3e4a {
  strings:
    $key_3e4a = { 69 38 [2] 5b 1a [2] 5d 2f [2] 73 2f [2] 4c 33 }

  condition:
    any of them
}