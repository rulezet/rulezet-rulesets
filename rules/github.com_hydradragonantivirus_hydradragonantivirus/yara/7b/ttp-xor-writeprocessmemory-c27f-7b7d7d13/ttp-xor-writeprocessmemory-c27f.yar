rule TTP_XOR_WriteProcessMemory_c27f {
  strings:
    $key_c27f = { 95 0d [2] a7 2f [2] a1 1a [2] 8f 1a [2] b0 06 }

  condition:
    any of them
}