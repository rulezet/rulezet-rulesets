rule TTP_XOR_WriteProcessMemory_ca8a {
  strings:
    $key_ca8a = { 9d f8 [2] af da [2] a9 ef [2] 87 ef [2] b8 f3 }

  condition:
    any of them
}