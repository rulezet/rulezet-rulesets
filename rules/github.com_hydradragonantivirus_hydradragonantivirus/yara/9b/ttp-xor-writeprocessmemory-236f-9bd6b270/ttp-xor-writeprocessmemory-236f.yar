rule TTP_XOR_WriteProcessMemory_236f {
  strings:
    $key_236f = { 74 1d [2] 46 3f [2] 40 0a [2] 6e 0a [2] 51 16 }

  condition:
    any of them
}