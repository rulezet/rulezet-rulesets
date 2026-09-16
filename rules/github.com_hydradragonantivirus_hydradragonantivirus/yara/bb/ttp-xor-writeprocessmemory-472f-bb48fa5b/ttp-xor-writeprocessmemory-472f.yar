rule TTP_XOR_WriteProcessMemory_472f {
  strings:
    $key_472f = { 10 5d [2] 22 7f [2] 24 4a [2] 0a 4a [2] 35 56 }

  condition:
    any of them
}