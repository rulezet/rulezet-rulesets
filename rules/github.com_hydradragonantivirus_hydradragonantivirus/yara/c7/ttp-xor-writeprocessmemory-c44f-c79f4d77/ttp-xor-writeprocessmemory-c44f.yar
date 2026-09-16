rule TTP_XOR_WriteProcessMemory_c44f {
  strings:
    $key_c44f = { 93 3d [2] a1 1f [2] a7 2a [2] 89 2a [2] b6 36 }

  condition:
    any of them
}