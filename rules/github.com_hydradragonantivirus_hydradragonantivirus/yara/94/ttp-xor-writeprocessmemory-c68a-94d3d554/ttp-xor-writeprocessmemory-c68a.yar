rule TTP_XOR_WriteProcessMemory_c68a {
  strings:
    $key_c68a = { 91 f8 [2] a3 da [2] a5 ef [2] 8b ef [2] b4 f3 }

  condition:
    any of them
}