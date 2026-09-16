rule TTP_XOR_WriteProcessMemory_c22d {
  strings:
    $key_c22d = { 95 5f [2] a7 7d [2] a1 48 [2] 8f 48 [2] b0 54 }

  condition:
    any of them
}