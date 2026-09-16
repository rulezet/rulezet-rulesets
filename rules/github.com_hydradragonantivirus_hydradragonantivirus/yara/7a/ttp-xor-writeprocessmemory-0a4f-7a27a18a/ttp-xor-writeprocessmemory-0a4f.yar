rule TTP_XOR_WriteProcessMemory_0a4f {
  strings:
    $key_0a4f = { 5d 3d [2] 6f 1f [2] 69 2a [2] 47 2a [2] 78 36 }

  condition:
    any of them
}