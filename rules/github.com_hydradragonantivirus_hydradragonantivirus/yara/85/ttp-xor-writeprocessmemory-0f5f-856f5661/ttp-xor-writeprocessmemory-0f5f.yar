rule TTP_XOR_WriteProcessMemory_0f5f {
  strings:
    $key_0f5f = { 58 2d [2] 6a 0f [2] 6c 3a [2] 42 3a [2] 7d 26 }

  condition:
    any of them
}