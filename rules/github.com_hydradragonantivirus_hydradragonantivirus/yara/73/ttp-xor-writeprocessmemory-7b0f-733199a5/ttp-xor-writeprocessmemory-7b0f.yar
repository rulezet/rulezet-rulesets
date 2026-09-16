rule TTP_XOR_WriteProcessMemory_7b0f {
  strings:
    $key_7b0f = { 2c 7d [2] 1e 5f [2] 18 6a [2] 36 6a [2] 09 76 }

  condition:
    any of them
}