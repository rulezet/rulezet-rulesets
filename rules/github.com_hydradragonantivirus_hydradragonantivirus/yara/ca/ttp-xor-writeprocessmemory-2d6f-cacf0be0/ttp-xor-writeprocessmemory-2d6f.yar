rule TTP_XOR_WriteProcessMemory_2d6f {
  strings:
    $key_2d6f = { 7a 1d [2] 48 3f [2] 4e 0a [2] 60 0a [2] 5f 16 }

  condition:
    any of them
}