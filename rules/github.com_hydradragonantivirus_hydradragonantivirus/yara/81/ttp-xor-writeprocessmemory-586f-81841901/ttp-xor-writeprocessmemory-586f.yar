rule TTP_XOR_WriteProcessMemory_586f {
  strings:
    $key_586f = { 0f 1d [2] 3d 3f [2] 3b 0a [2] 15 0a [2] 2a 16 }

  condition:
    any of them
}