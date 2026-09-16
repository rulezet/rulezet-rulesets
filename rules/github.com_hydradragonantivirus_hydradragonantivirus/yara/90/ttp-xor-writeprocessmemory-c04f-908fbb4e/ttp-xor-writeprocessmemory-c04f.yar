rule TTP_XOR_WriteProcessMemory_c04f {
  strings:
    $key_c04f = { 97 3d [2] a5 1f [2] a3 2a [2] 8d 2a [2] b2 36 }

  condition:
    any of them
}