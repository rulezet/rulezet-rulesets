rule TTP_XOR_WriteProcessMemory_d41f {
  strings:
    $key_d41f = { 83 6d [2] b1 4f [2] b7 7a [2] 99 7a [2] a6 66 }

  condition:
    any of them
}