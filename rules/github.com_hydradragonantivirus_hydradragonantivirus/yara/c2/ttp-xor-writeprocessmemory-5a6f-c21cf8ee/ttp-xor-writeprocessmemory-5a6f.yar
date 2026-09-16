rule TTP_XOR_WriteProcessMemory_5a6f {
  strings:
    $key_5a6f = { 0d 1d [2] 3f 3f [2] 39 0a [2] 17 0a [2] 28 16 }

  condition:
    any of them
}