rule TTP_XOR_WriteProcessMemory_c26f {
  strings:
    $key_c26f = { 95 1d [2] a7 3f [2] a1 0a [2] 8f 0a [2] b0 16 }

  condition:
    any of them
}