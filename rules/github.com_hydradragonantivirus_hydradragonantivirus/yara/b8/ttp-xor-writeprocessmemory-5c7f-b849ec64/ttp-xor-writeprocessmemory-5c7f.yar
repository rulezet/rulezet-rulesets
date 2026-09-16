rule TTP_XOR_WriteProcessMemory_5c7f {
  strings:
    $key_5c7f = { 0b 0d [2] 39 2f [2] 3f 1a [2] 11 1a [2] 2e 06 }

  condition:
    any of them
}