rule TTP_XOR_WriteProcessMemory_d17f {
  strings:
    $key_d17f = { 86 0d [2] b4 2f [2] b2 1a [2] 9c 1a [2] a3 06 }

  condition:
    any of them
}