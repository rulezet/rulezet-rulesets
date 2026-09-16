rule TTP_XOR_WriteProcessMemory_481f {
  strings:
    $key_481f = { 1f 6d [2] 2d 4f [2] 2b 7a [2] 05 7a [2] 3a 66 }

  condition:
    any of them
}