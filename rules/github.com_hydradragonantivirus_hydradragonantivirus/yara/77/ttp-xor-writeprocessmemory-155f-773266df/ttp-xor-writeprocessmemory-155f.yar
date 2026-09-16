rule TTP_XOR_WriteProcessMemory_155f {
  strings:
    $key_155f = { 42 2d [2] 70 0f [2] 76 3a [2] 58 3a [2] 67 26 }

  condition:
    any of them
}