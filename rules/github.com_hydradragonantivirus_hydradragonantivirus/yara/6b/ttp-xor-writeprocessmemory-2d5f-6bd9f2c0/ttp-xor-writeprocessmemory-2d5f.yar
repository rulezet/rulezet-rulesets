rule TTP_XOR_WriteProcessMemory_2d5f {
  strings:
    $key_2d5f = { 7a 2d [2] 48 0f [2] 4e 3a [2] 60 3a [2] 5f 26 }

  condition:
    any of them
}