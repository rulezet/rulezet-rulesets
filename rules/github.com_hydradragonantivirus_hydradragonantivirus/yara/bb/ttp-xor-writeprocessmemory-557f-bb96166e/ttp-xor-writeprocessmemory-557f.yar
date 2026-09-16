rule TTP_XOR_WriteProcessMemory_557f {
  strings:
    $key_557f = { 02 0d [2] 30 2f [2] 36 1a [2] 18 1a [2] 27 06 }

  condition:
    any of them
}