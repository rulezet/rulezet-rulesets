rule TTP_XOR_WriteProcessMemory_d29d {
  strings:
    $key_d29d = { 85 ef [2] b7 cd [2] b1 f8 [2] 9f f8 [2] a0 e4 }

  condition:
    any of them
}