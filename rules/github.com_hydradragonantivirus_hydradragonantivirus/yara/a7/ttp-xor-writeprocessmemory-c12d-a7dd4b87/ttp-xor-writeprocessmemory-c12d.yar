rule TTP_XOR_WriteProcessMemory_c12d {
  strings:
    $key_c12d = { 96 5f [2] a4 7d [2] a2 48 [2] 8c 48 [2] b3 54 }

  condition:
    any of them
}