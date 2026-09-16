rule TTP_XOR_WriteProcessMemory_457f {
  strings:
    $key_457f = { 12 0d [2] 20 2f [2] 26 1a [2] 08 1a [2] 37 06 }

  condition:
    any of them
}