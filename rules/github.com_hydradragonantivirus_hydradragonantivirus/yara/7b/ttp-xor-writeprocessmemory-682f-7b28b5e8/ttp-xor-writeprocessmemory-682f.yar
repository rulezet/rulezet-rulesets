rule TTP_XOR_WriteProcessMemory_682f {
  strings:
    $key_682f = { 3f 5d [2] 0d 7f [2] 0b 4a [2] 25 4a [2] 1a 56 }

  condition:
    any of them
}