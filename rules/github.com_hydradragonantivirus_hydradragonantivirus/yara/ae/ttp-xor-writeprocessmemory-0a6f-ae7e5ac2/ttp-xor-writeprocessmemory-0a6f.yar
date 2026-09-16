rule TTP_XOR_WriteProcessMemory_0a6f {
  strings:
    $key_0a6f = { 5d 1d [2] 6f 3f [2] 69 0a [2] 47 0a [2] 78 16 }

  condition:
    any of them
}