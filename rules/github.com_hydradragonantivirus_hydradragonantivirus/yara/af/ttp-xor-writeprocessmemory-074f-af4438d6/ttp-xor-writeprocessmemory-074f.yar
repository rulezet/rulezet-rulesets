rule TTP_XOR_WriteProcessMemory_074f {
  strings:
    $key_074f = { 50 3d [2] 62 1f [2] 64 2a [2] 4a 2a [2] 75 36 }

  condition:
    any of them
}