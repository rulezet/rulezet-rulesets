rule TTP_XOR_WriteProcessMemory_135f {
  strings:
    $key_135f = { 44 2d [2] 76 0f [2] 70 3a [2] 5e 3a [2] 61 26 }

  condition:
    any of them
}