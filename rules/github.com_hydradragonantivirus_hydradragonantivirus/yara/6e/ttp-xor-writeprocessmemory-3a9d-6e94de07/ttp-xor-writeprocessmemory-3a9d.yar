rule TTP_XOR_WriteProcessMemory_3a9d {
  strings:
    $key_3a9d = { 6d ef [2] 5f cd [2] 59 f8 [2] 77 f8 [2] 48 e4 }

  condition:
    any of them
}