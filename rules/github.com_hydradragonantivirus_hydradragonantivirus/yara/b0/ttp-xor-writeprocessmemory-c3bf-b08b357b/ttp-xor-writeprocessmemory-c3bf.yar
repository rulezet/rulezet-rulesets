rule TTP_XOR_WriteProcessMemory_c3bf {
  strings:
    $key_c3bf = { 94 cd [2] a6 ef [2] a0 da [2] 8e da [2] b1 c6 }

  condition:
    any of them
}