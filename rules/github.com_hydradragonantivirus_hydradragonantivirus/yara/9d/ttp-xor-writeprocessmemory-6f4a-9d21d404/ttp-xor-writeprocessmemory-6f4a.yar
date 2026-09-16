rule TTP_XOR_WriteProcessMemory_6f4a {
  strings:
    $key_6f4a = { 38 38 [2] 0a 1a [2] 0c 2f [2] 22 2f [2] 1d 33 }

  condition:
    any of them
}