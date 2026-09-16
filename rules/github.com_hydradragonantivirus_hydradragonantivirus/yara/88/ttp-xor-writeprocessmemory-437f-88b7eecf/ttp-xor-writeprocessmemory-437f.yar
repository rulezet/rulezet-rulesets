rule TTP_XOR_WriteProcessMemory_437f {
  strings:
    $key_437f = { 14 0d [2] 26 2f [2] 20 1a [2] 0e 1a [2] 31 06 }

  condition:
    any of them
}