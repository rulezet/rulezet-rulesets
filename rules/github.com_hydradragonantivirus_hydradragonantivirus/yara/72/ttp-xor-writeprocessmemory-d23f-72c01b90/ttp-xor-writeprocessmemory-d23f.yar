rule TTP_XOR_WriteProcessMemory_d23f {
  strings:
    $key_d23f = { 85 4d [2] b7 6f [2] b1 5a [2] 9f 5a [2] a0 46 }

  condition:
    any of them
}