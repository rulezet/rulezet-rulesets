rule TTP_XOR_WriteProcessMemory_477f {
  strings:
    $key_477f = { 10 0d [2] 22 2f [2] 24 1a [2] 0a 1a [2] 35 06 }

  condition:
    any of them
}