rule TTP_XOR_WriteProcessMemory_7d9d {
  strings:
    $key_7d9d = { 2a ef [2] 18 cd [2] 1e f8 [2] 30 f8 [2] 0f e4 }

  condition:
    any of them
}