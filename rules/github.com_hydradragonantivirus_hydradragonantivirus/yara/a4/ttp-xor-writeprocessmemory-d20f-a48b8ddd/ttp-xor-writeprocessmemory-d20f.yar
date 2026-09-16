rule TTP_XOR_WriteProcessMemory_d20f {
  strings:
    $key_d20f = { 85 7d [2] b7 5f [2] b1 6a [2] 9f 6a [2] a0 76 }

  condition:
    any of them
}