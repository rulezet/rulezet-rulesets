rule TTP_XOR_WriteProcessMemory_235f {
  strings:
    $key_235f = { 74 2d [2] 46 0f [2] 40 3a [2] 6e 3a [2] 51 26 }

  condition:
    any of them
}