rule TTP_XOR_WriteProcessMemory_485f {
  strings:
    $key_485f = { 1f 2d [2] 2d 0f [2] 2b 3a [2] 05 3a [2] 3a 26 }

  condition:
    any of them
}