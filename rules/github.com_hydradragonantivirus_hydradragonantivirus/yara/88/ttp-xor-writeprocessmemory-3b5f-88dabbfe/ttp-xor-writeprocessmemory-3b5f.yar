rule TTP_XOR_WriteProcessMemory_3b5f {
  strings:
    $key_3b5f = { 6c 2d [2] 5e 0f [2] 58 3a [2] 76 3a [2] 49 26 }

  condition:
    any of them
}