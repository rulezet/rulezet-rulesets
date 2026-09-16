rule TTP_XOR_WriteProcessMemory_575f {
  strings:
    $key_575f = { 00 2d [2] 32 0f [2] 34 3a [2] 1a 3a [2] 25 26 }

  condition:
    any of them
}