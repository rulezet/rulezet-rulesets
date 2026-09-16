rule TTP_XOR_WriteProcessMemory_c53d {
  strings:
    $key_c53d = { 92 4f [2] a0 6d [2] a6 58 [2] 88 58 [2] b7 44 }

  condition:
    any of them
}