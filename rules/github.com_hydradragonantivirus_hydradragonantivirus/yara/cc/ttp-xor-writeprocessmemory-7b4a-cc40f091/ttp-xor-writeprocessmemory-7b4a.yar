rule TTP_XOR_WriteProcessMemory_7b4a {
  strings:
    $key_7b4a = { 2c 38 [2] 1e 1a [2] 18 2f [2] 36 2f [2] 09 33 }

  condition:
    any of them
}