rule TTP_XOR_WriteProcessMemory_084f {
  strings:
    $key_084f = { 5f 3d [2] 6d 1f [2] 6b 2a [2] 45 2a [2] 7a 36 }

  condition:
    any of them
}