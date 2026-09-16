rule TTP_XOR_WriteProcessMemory_447f {
  strings:
    $key_447f = { 13 0d [2] 21 2f [2] 27 1a [2] 09 1a [2] 36 06 }

  condition:
    any of them
}