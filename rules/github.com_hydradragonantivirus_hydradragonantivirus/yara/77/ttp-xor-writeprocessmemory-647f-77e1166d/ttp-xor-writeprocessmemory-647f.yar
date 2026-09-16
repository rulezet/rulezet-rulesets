rule TTP_XOR_WriteProcessMemory_647f {
  strings:
    $key_647f = { 33 0d [2] 01 2f [2] 07 1a [2] 29 1a [2] 16 06 }

  condition:
    any of them
}