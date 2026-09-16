rule TTP_XOR_WriteProcessMemory_c65f {
  strings:
    $key_c65f = { 91 2d [2] a3 0f [2] a5 3a [2] 8b 3a [2] b4 26 }

  condition:
    any of them
}