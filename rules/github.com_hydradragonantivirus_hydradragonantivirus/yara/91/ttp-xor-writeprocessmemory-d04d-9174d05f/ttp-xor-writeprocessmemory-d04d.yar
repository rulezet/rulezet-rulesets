rule TTP_XOR_WriteProcessMemory_d04d {
  strings:
    $key_d04d = { 87 3f [2] b5 1d [2] b3 28 [2] 9d 28 [2] a2 34 }

  condition:
    any of them
}