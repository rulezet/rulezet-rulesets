rule TTP_XOR_WriteProcessMemory_697f {
  strings:
    $key_697f = { 3e 0d [2] 0c 2f [2] 0a 1a [2] 24 1a [2] 1b 06 }

  condition:
    any of them
}