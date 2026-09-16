rule TTP_XOR_WriteProcessMemory_d68a {
  strings:
    $key_d68a = { 81 f8 [2] b3 da [2] b5 ef [2] 9b ef [2] a4 f3 }

  condition:
    any of them
}