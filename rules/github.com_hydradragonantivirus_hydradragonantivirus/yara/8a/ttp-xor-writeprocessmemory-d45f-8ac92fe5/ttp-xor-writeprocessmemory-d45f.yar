rule TTP_XOR_WriteProcessMemory_d45f {
  strings:
    $key_d45f = { 83 2d [2] b1 0f [2] b7 3a [2] 99 3a [2] a6 26 }

  condition:
    any of them
}