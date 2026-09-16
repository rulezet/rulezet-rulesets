rule TTP_XOR_WriteProcessMemory_1d6f {
  strings:
    $key_1d6f = { 4a 1d [2] 78 3f [2] 7e 0a [2] 50 0a [2] 6f 16 }

  condition:
    any of them
}