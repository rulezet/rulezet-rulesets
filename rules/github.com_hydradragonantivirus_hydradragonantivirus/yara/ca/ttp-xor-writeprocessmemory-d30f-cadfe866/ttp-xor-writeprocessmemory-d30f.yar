rule TTP_XOR_WriteProcessMemory_d30f {
  strings:
    $key_d30f = { 84 7d [2] b6 5f [2] b0 6a [2] 9e 6a [2] a1 76 }

  condition:
    any of them
}