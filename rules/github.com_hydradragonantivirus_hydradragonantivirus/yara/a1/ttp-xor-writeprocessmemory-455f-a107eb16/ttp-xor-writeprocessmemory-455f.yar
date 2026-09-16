rule TTP_XOR_WriteProcessMemory_455f {
  strings:
    $key_455f = { 12 2d [2] 20 0f [2] 26 3a [2] 08 3a [2] 37 26 }

  condition:
    any of them
}