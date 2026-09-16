rule TTP_XOR_WriteProcessMemory_346f {
  strings:
    $key_346f = { 63 1d [2] 51 3f [2] 57 0a [2] 79 0a [2] 46 16 }

  condition:
    any of them
}