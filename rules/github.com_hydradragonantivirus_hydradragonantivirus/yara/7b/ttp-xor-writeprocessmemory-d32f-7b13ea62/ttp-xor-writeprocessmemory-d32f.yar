rule TTP_XOR_WriteProcessMemory_d32f {
  strings:
    $key_d32f = { 84 5d [2] b6 7f [2] b0 4a [2] 9e 4a [2] a1 56 }

  condition:
    any of them
}