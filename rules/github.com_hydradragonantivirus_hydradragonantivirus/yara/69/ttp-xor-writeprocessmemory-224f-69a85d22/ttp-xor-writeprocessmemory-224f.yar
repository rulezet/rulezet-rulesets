rule TTP_XOR_WriteProcessMemory_224f {
  strings:
    $key_224f = { 75 3d [2] 47 1f [2] 41 2a [2] 6f 2a [2] 50 36 }

  condition:
    any of them
}