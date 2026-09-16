rule TTP_XOR_WriteProcessMemory_c71f {
  strings:
    $key_c71f = { 90 6d [2] a2 4f [2] a4 7a [2] 8a 7a [2] b5 66 }

  condition:
    any of them
}