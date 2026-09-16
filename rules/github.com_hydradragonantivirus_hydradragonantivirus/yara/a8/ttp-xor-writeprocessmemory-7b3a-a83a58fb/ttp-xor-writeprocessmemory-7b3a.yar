rule TTP_XOR_WriteProcessMemory_7b3a {
  strings:
    $key_7b3a = { 2c 48 [2] 1e 6a [2] 18 5f [2] 36 5f [2] 09 43 }

  condition:
    any of them
}