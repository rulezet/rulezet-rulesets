rule TTP_XOR_WriteProcessMemory_d34f {
  strings:
    $key_d34f = { 84 3d [2] b6 1f [2] b0 2a [2] 9e 2a [2] a1 36 }

  condition:
    any of them
}