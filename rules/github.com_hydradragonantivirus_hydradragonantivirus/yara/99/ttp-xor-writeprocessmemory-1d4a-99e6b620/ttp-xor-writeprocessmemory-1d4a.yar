rule TTP_XOR_WriteProcessMemory_1d4a {
  strings:
    $key_1d4a = { 4a 38 [2] 78 1a [2] 7e 2f [2] 50 2f [2] 6f 33 }

  condition:
    any of them
}