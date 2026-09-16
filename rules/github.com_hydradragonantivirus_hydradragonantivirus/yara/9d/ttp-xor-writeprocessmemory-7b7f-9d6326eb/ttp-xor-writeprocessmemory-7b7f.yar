rule TTP_XOR_WriteProcessMemory_7b7f {
  strings:
    $key_7b7f = { 2c 0d [2] 1e 2f [2] 18 1a [2] 36 1a [2] 09 06 }

  condition:
    any of them
}