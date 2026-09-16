rule TTP_XOR_WriteProcessMemory_515f {
  strings:
    $key_515f = { 06 2d [2] 34 0f [2] 32 3a [2] 1c 3a [2] 23 26 }

  condition:
    any of them
}