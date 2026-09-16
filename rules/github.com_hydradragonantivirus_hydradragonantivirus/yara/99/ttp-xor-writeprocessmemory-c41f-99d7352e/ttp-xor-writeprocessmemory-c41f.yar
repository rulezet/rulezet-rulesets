rule TTP_XOR_WriteProcessMemory_c41f {
  strings:
    $key_c41f = { 93 6d [2] a1 4f [2] a7 7a [2] 89 7a [2] b6 66 }

  condition:
    any of them
}