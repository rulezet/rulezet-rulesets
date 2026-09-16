rule TTP_XOR_WriteProcessMemory_d25f {
  strings:
    $key_d25f = { 85 2d [2] b7 0f [2] b1 3a [2] 9f 3a [2] a0 26 }

  condition:
    any of them
}