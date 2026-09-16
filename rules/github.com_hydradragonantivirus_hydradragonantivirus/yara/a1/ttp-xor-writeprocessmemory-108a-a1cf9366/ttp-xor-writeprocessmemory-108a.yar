rule TTP_XOR_WriteProcessMemory_108a {
  strings:
    $key_108a = { 47 f8 [2] 75 da [2] 73 ef [2] 5d ef [2] 62 f3 }

  condition:
    any of them
}