rule TTP_XOR_WriteProcessMemory_1f5f {
  strings:
    $key_1f5f = { 48 2d [2] 7a 0f [2] 7c 3a [2] 52 3a [2] 6d 26 }

  condition:
    any of them
}