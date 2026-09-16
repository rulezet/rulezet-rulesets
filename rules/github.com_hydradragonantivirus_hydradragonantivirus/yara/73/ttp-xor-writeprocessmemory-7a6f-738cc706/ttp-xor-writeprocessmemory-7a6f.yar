rule TTP_XOR_WriteProcessMemory_7a6f {
  strings:
    $key_7a6f = { 2d 1d [2] 1f 3f [2] 19 0a [2] 37 0a [2] 08 16 }

  condition:
    any of them
}