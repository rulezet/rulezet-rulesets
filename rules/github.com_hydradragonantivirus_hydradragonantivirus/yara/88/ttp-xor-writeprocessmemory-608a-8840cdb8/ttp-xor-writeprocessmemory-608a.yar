rule TTP_XOR_WriteProcessMemory_608a {
  strings:
    $key_608a = { 37 f8 [2] 05 da [2] 03 ef [2] 2d ef [2] 12 f3 }

  condition:
    any of them
}