rule TTP_XOR_WriteProcessMemory_fa5f {
  strings:
    $key_fa5f = { ad 2d [2] 9f 0f [2] 99 3a [2] b7 3a [2] 88 26 }

  condition:
    any of them
}