rule TTP_XOR_WriteProcessMemory_187f {
  strings:
    $key_187f = { 4f 0d [2] 7d 2f [2] 7b 1a [2] 55 1a [2] 6a 06 }

  condition:
    any of them
}