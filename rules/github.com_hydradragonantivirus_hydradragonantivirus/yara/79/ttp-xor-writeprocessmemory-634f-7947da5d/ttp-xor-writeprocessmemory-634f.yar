rule TTP_XOR_WriteProcessMemory_634f {
  strings:
    $key_634f = { 34 3d [2] 06 1f [2] 00 2a [2] 2e 2a [2] 11 36 }

  condition:
    any of them
}