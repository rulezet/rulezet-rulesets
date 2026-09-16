rule TTP_XOR_WriteProcessMemory_d11f {
  strings:
    $key_d11f = { 86 6d [2] b4 4f [2] b2 7a [2] 9c 7a [2] a3 66 }

  condition:
    any of them
}