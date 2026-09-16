rule TTP_XOR_WriteProcessMemory_d22f {
  strings:
    $key_d22f = { 85 5d [2] b7 7f [2] b1 4a [2] 9f 4a [2] a0 56 }

  condition:
    any of them
}