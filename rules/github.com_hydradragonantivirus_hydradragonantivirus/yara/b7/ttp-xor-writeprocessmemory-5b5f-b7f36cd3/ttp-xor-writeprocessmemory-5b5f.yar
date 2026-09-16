rule TTP_XOR_WriteProcessMemory_5b5f {
  strings:
    $key_5b5f = { 0c 2d [2] 3e 0f [2] 38 3a [2] 16 3a [2] 29 26 }

  condition:
    any of them
}