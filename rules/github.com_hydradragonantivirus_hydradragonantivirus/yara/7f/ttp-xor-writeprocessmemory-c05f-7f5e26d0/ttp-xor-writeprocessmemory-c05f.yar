rule TTP_XOR_WriteProcessMemory_c05f {
  strings:
    $key_c05f = { 97 2d [2] a5 0f [2] a3 3a [2] 8d 3a [2] b2 26 }

  condition:
    any of them
}