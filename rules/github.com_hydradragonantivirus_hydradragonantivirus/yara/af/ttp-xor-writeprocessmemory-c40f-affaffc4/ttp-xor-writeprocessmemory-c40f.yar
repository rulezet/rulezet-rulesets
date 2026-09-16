rule TTP_XOR_WriteProcessMemory_c40f {
  strings:
    $key_c40f = { 93 7d [2] a1 5f [2] a7 6a [2] 89 6a [2] b6 76 }

  condition:
    any of them
}