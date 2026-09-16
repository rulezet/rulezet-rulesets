rule TTP_XOR_WriteProcessMemory_176f {
  strings:
    $key_176f = { 40 1d [2] 72 3f [2] 74 0a [2] 5a 0a [2] 65 16 }

  condition:
    any of them
}