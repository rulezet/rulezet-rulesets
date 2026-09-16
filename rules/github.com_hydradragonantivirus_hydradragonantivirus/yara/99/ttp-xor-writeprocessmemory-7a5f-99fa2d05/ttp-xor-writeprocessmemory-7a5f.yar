rule TTP_XOR_WriteProcessMemory_7a5f {
  strings:
    $key_7a5f = { 2d 2d [2] 1f 0f [2] 19 3a [2] 37 3a [2] 08 26 }

  condition:
    any of them
}