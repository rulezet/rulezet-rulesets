rule TTP_XOR_WriteProcessMemory_2d4a {
  strings:
    $key_2d4a = { 7a 38 [2] 48 1a [2] 4e 2f [2] 60 2f [2] 5f 33 }

  condition:
    any of them
}