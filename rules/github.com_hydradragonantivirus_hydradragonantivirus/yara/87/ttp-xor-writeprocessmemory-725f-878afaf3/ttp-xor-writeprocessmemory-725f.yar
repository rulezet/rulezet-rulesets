rule TTP_XOR_WriteProcessMemory_725f {
  strings:
    $key_725f = { 25 2d [2] 17 0f [2] 11 3a [2] 3f 3a [2] 00 26 }

  condition:
    any of them
}