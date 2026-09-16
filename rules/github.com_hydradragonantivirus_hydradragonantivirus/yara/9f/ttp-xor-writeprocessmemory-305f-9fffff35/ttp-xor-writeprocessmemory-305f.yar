rule TTP_XOR_WriteProcessMemory_305f {
  strings:
    $key_305f = { 67 2d [2] 55 0f [2] 53 3a [2] 7d 3a [2] 42 26 }

  condition:
    any of them
}