rule TTP_XOR_WriteProcessMemory_2a9d {
  strings:
    $key_2a9d = { 7d ef [2] 4f cd [2] 49 f8 [2] 67 f8 [2] 58 e4 }

  condition:
    any of them
}