rule TTP_XOR_WriteProcessMemory_628a {
  strings:
    $key_628a = { 35 f8 [2] 07 da [2] 01 ef [2] 2f ef [2] 10 f3 }

  condition:
    any of them
}