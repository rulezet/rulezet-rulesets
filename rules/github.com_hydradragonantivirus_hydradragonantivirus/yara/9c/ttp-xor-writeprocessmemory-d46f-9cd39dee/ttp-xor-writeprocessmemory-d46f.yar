rule TTP_XOR_WriteProcessMemory_d46f {
  strings:
    $key_d46f = { 83 1d [2] b1 3f [2] b7 0a [2] 99 0a [2] a6 16 }

  condition:
    any of them
}