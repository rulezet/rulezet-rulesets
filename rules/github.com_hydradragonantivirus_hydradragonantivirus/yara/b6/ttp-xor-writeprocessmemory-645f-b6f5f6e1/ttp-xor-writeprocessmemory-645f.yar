rule TTP_XOR_WriteProcessMemory_645f {
  strings:
    $key_645f = { 33 2d [2] 01 0f [2] 07 3a [2] 29 3a [2] 16 26 }

  condition:
    any of them
}