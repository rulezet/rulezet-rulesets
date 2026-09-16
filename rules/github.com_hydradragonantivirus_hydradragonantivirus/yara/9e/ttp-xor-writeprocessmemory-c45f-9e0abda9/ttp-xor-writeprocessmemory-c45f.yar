rule TTP_XOR_WriteProcessMemory_c45f {
  strings:
    $key_c45f = { 93 2d [2] a1 0f [2] a7 3a [2] 89 3a [2] b6 26 }

  condition:
    any of them
}