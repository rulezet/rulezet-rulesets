rule TTP_XOR_WriteProcessMemory_7a0f {
  strings:
    $key_7a0f = { 2d 7d [2] 1f 5f [2] 19 6a [2] 37 6a [2] 08 76 }

  condition:
    any of them
}