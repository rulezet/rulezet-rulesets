rule TTP_XOR_WriteProcessMemory_615f {
  strings:
    $key_615f = { 36 2d [2] 04 0f [2] 02 3a [2] 2c 3a [2] 13 26 }

  condition:
    any of them
}