rule TTP_XOR_WriteProcessMemory_0a9d {
  strings:
    $key_0a9d = { 5d ef [2] 6f cd [2] 69 f8 [2] 47 f8 [2] 78 e4 }

  condition:
    any of them
}