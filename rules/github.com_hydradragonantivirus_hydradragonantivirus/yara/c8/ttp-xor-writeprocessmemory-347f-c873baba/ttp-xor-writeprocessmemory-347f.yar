rule TTP_XOR_WriteProcessMemory_347f {
  strings:
    $key_347f = { 63 0d [2] 51 2f [2] 57 1a [2] 79 1a [2] 46 06 }

  condition:
    any of them
}