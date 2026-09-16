rule TTP_XOR_WriteProcessMemory_c72d {
  strings:
    $key_c72d = { 90 5f [2] a2 7d [2] a4 48 [2] 8a 48 [2] b5 54 }

  condition:
    any of them
}