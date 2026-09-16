rule TTP_XOR_WriteProcessMemory_025f {
  strings:
    $key_025f = { 55 2d [2] 67 0f [2] 61 3a [2] 4f 3a [2] 70 26 }

  condition:
    any of them
}