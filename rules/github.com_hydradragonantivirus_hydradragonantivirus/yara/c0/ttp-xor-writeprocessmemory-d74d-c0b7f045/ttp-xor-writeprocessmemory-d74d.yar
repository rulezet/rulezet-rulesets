rule TTP_XOR_WriteProcessMemory_d74d {
  strings:
    $key_d74d = { 80 3f [2] b2 1d [2] b4 28 [2] 9a 28 [2] a5 34 }

  condition:
    any of them
}