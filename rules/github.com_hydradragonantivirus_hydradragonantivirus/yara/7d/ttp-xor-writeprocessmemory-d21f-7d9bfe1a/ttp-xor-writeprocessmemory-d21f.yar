rule TTP_XOR_WriteProcessMemory_d21f {
  strings:
    $key_d21f = { 85 6d [2] b7 4f [2] b1 7a [2] 9f 7a [2] a0 66 }

  condition:
    any of them
}