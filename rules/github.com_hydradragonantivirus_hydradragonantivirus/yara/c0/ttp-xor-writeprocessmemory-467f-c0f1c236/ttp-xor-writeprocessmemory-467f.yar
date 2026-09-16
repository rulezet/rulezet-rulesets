rule TTP_XOR_WriteProcessMemory_467f {
  strings:
    $key_467f = { 11 0d [2] 23 2f [2] 25 1a [2] 0b 1a [2] 34 06 }

  condition:
    any of them
}