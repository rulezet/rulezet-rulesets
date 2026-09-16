rule TTP_XOR_WriteProcessMemory_c41d {
  strings:
    $key_c41d = { 93 6f [2] a1 4d [2] a7 78 [2] 89 78 [2] b6 64 }

  condition:
    any of them
}