rule TTP_XOR_WriteProcessMemory_0d5f {
  strings:
    $key_0d5f = { 5a 2d [2] 68 0f [2] 6e 3a [2] 40 3a [2] 7f 26 }

  condition:
    any of them
}