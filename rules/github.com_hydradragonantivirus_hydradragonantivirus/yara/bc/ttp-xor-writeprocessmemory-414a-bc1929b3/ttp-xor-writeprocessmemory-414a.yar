rule TTP_XOR_WriteProcessMemory_414a {
  strings:
    $key_414a = { 16 38 [2] 24 1a [2] 22 2f [2] 0c 2f [2] 33 33 }

  condition:
    any of them
}