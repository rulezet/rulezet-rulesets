rule TTP_XOR_WriteProcessMemory_d54d {
  strings:
    $key_d54d = { 82 3f [2] b0 1d [2] b6 28 [2] 98 28 [2] a7 34 }

  condition:
    any of them
}