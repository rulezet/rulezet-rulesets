rule TTP_XOR_WriteProcessMemory_630f {
  strings:
    $key_630f = { 34 7d [2] 06 5f [2] 00 6a [2] 2e 6a [2] 11 76 }

  condition:
    any of them
}