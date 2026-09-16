rule TTP_XOR_WriteProcessMemory_d65d {
  strings:
    $key_d65d = { 81 2f [2] b3 0d [2] b5 38 [2] 9b 38 [2] a4 24 }

  condition:
    any of them
}