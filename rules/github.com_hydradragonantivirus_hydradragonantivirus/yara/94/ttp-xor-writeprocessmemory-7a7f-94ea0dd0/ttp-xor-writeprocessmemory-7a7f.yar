rule TTP_XOR_WriteProcessMemory_7a7f {
  strings:
    $key_7a7f = { 2d 0d [2] 1f 2f [2] 19 1a [2] 37 1a [2] 08 06 }

  condition:
    any of them
}