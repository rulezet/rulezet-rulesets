rule TTP_XOR_WriteProcessMemory_d12f {
  strings:
    $key_d12f = { 86 5d [2] b4 7f [2] b2 4a [2] 9c 4a [2] a3 56 }

  condition:
    any of them
}