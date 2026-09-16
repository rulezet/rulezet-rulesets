rule TTP_XOR_WriteProcessMemory_616f {
  strings:
    $key_616f = { 36 1d [2] 04 3f [2] 02 0a [2] 2c 0a [2] 13 16 }

  condition:
    any of them
}