rule TTP_XOR_WriteProcessMemory_c77f {
  strings:
    $key_c77f = { 90 0d [2] a2 2f [2] a4 1a [2] 8a 1a [2] b5 06 }

  condition:
    any of them
}