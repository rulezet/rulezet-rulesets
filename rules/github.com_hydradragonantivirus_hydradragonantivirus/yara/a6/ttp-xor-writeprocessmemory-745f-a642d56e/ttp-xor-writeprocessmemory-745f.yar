rule TTP_XOR_WriteProcessMemory_745f {
  strings:
    $key_745f = { 23 2d [2] 11 0f [2] 17 3a [2] 39 3a [2] 06 26 }

  condition:
    any of them
}