rule TTP_XOR_WriteProcessMemory_404f {
  strings:
    $key_404f = { 17 3d [2] 25 1f [2] 23 2a [2] 0d 2a [2] 32 36 }

  condition:
    any of them
}