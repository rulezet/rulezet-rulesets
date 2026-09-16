rule TTP_XOR_WriteProcessMemory_d34d {
  strings:
    $key_d34d = { 84 3f [2] b6 1d [2] b0 28 [2] 9e 28 [2] a1 34 }

  condition:
    any of them
}