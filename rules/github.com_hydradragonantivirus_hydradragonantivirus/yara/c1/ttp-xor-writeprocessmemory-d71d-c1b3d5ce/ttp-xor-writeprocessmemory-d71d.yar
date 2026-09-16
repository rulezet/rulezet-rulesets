rule TTP_XOR_WriteProcessMemory_d71d {
  strings:
    $key_d71d = { 80 6f [2] b2 4d [2] b4 78 [2] 9a 78 [2] a5 64 }

  condition:
    any of them
}