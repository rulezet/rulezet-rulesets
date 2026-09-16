rule TTP_XOR_WriteProcessMemory_c34f {
  strings:
    $key_c34f = { 94 3d [2] a6 1f [2] a0 2a [2] 8e 2a [2] b1 36 }

  condition:
    any of them
}