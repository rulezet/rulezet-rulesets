rule TTP_XOR_WriteProcessMemory_c21d {
  strings:
    $key_c21d = { 95 6f [2] a7 4d [2] a1 78 [2] 8f 78 [2] b0 64 }

  condition:
    any of them
}