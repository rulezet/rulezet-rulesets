rule TTP_XOR_WriteProcessMemory_474f {
  strings:
    $key_474f = { 10 3d [2] 22 1f [2] 24 2a [2] 0a 2a [2] 35 36 }

  condition:
    any of them
}