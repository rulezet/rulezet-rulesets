rule TTP_XOR_WriteProcessMemory_d15f {
  strings:
    $key_d15f = { 86 2d [2] b4 0f [2] b2 3a [2] 9c 3a [2] a3 26 }

  condition:
    any of them
}