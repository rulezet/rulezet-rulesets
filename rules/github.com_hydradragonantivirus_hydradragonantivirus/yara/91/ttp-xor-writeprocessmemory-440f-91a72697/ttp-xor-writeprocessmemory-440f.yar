rule TTP_XOR_WriteProcessMemory_440f {
  strings:
    $key_440f = { 13 7d [2] 21 5f [2] 27 6a [2] 09 6a [2] 36 76 }

  condition:
    any of them
}