rule TTP_XOR_WriteProcessMemory_507f {
  strings:
    $key_507f = { 07 0d [2] 35 2f [2] 33 1a [2] 1d 1a [2] 22 06 }

  condition:
    any of them
}