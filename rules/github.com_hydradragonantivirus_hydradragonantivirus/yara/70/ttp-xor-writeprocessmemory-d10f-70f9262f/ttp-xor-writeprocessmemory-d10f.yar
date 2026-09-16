rule TTP_XOR_WriteProcessMemory_d10f {
  strings:
    $key_d10f = { 86 7d [2] b4 5f [2] b2 6a [2] 9c 6a [2] a3 76 }

  condition:
    any of them
}