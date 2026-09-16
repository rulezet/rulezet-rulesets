rule TTP_XOR_WriteProcessMemory_4a6f {
  strings:
    $key_4a6f = { 1d 1d [2] 2f 3f [2] 29 0a [2] 07 0a [2] 38 16 }

  condition:
    any of them
}