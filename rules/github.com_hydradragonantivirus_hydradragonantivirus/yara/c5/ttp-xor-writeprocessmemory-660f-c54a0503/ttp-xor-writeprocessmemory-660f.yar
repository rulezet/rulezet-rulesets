rule TTP_XOR_WriteProcessMemory_660f {
  strings:
    $key_660f = { 31 7d [2] 03 5f [2] 05 6a [2] 2b 6a [2] 14 76 }

  condition:
    any of them
}