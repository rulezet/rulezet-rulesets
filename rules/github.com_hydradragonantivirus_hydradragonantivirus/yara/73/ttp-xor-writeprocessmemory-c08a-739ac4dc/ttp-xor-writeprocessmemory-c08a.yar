rule TTP_XOR_WriteProcessMemory_c08a {
  strings:
    $key_c08a = { 97 f8 [2] a5 da [2] a3 ef [2] 8d ef [2] b2 f3 }

  condition:
    any of them
}