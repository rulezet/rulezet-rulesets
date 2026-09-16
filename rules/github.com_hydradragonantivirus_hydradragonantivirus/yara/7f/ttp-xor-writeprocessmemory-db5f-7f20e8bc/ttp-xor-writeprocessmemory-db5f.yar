rule TTP_XOR_WriteProcessMemory_db5f {
  strings:
    $key_db5f = { 8c 2d [2] be 0f [2] b8 3a [2] 96 3a [2] a9 26 }

  condition:
    any of them
}