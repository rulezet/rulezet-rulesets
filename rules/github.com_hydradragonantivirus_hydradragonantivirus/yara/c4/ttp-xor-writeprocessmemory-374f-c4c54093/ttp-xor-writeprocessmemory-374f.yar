rule TTP_XOR_WriteProcessMemory_374f {
  strings:
    $key_374f = { 60 3d [2] 52 1f [2] 54 2a [2] 7a 2a [2] 45 36 }

  condition:
    any of them
}