rule TTP_XOR_WriteProcessMemory_c76f {
  strings:
    $key_c76f = { 90 1d [2] a2 3f [2] a4 0a [2] 8a 0a [2] b5 16 }

  condition:
    any of them
}