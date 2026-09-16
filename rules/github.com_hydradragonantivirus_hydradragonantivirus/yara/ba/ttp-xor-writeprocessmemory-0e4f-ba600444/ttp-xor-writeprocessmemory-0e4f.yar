rule TTP_XOR_WriteProcessMemory_0e4f {
  strings:
    $key_0e4f = { 59 3d [2] 6b 1f [2] 6d 2a [2] 43 2a [2] 7c 36 }

  condition:
    any of them
}