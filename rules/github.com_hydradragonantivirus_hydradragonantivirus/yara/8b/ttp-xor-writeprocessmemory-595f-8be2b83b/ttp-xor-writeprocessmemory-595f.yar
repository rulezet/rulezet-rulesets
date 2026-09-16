rule TTP_XOR_WriteProcessMemory_595f {
  strings:
    $key_595f = { 0e 2d [2] 3c 0f [2] 3a 3a [2] 14 3a [2] 2b 26 }

  condition:
    any of them
}