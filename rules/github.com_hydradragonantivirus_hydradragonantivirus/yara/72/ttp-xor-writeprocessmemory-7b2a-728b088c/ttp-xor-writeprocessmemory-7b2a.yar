rule TTP_XOR_WriteProcessMemory_7b2a {
  strings:
    $key_7b2a = { 2c 58 [2] 1e 7a [2] 18 4f [2] 36 4f [2] 09 53 }

  condition:
    any of them
}