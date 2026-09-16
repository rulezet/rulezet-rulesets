rule TTP_XOR_WriteProcessMemory_c25f {
  strings:
    $key_c25f = { 95 2d [2] a7 0f [2] a1 3a [2] 8f 3a [2] b0 26 }

  condition:
    any of them
}