rule TTP_XOR_WriteProcessMemory_326f {
  strings:
    $key_326f = { 65 1d [2] 57 3f [2] 51 0a [2] 7f 0a [2] 40 16 }

  condition:
    any of them
}