rule TTP_XOR_WriteProcessMemory_d70f {
  strings:
    $key_d70f = { 80 7d [2] b2 5f [2] b4 6a [2] 9a 6a [2] a5 76 }

  condition:
    any of them
}