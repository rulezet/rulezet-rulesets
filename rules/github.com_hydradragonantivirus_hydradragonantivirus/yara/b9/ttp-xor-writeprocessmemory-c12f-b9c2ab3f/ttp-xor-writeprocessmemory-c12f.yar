rule TTP_XOR_WriteProcessMemory_c12f {
  strings:
    $key_c12f = { 96 5d [2] a4 7f [2] a2 4a [2] 8c 4a [2] b3 56 }

  condition:
    any of them
}