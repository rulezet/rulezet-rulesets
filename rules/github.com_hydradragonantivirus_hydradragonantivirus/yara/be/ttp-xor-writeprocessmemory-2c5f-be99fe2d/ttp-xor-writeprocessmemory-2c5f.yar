rule TTP_XOR_WriteProcessMemory_2c5f {
  strings:
    $key_2c5f = { 7b 2d [2] 49 0f [2] 4f 3a [2] 61 3a [2] 5e 26 }

  condition:
    any of them
}