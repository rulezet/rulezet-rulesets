rule TTP_XOR_WriteProcessMemory_7b2f {
  strings:
    $key_7b2f = { 2c 5d [2] 1e 7f [2] 18 4a [2] 36 4a [2] 09 56 }

  condition:
    any of them
}