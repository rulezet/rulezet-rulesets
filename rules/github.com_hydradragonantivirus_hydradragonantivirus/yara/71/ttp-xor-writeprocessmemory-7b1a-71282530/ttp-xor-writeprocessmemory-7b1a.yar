rule TTP_XOR_WriteProcessMemory_7b1a {
  strings:
    $key_7b1a = { 2c 68 [2] 1e 4a [2] 18 7f [2] 36 7f [2] 09 63 }

  condition:
    any of them
}