rule TTP_XOR_WriteProcessMemory_d42f {
  strings:
    $key_d42f = { 83 5d [2] b1 7f [2] b7 4a [2] 99 4a [2] a6 56 }

  condition:
    any of them
}