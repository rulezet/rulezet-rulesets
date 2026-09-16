rule TTP_XOR_WriteProcessMemory_430f {
  strings:
    $key_430f = { 14 7d [2] 26 5f [2] 20 6a [2] 0e 6a [2] 31 76 }

  condition:
    any of them
}