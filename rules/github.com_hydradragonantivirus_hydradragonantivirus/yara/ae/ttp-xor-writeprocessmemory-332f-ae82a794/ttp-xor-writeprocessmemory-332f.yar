rule TTP_XOR_WriteProcessMemory_332f {
  strings:
    $key_332f = { 64 5d [2] 56 7f [2] 50 4a [2] 7e 4a [2] 41 56 }

  condition:
    any of them
}