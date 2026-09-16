rule TTP_XOR_WriteProcessMemory_508a {
  strings:
    $key_508a = { 07 f8 [2] 35 da [2] 33 ef [2] 1d ef [2] 22 f3 }

  condition:
    any of them
}