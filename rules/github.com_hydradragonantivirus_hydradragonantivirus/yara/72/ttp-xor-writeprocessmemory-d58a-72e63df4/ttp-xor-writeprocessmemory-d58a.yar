rule TTP_XOR_WriteProcessMemory_d58a {
  strings:
    $key_d58a = { 82 f8 [2] b0 da [2] b6 ef [2] 98 ef [2] a7 f3 }

  condition:
    any of them
}