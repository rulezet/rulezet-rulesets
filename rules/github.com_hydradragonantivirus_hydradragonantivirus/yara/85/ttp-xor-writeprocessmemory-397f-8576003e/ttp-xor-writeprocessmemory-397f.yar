rule TTP_XOR_WriteProcessMemory_397f {
  strings:
    $key_397f = { 6e 0d [2] 5c 2f [2] 5a 1a [2] 74 1a [2] 4b 06 }

  condition:
    any of them
}