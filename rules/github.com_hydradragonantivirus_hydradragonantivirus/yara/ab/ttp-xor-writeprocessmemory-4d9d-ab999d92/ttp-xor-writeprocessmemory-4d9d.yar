rule TTP_XOR_WriteProcessMemory_4d9d {
  strings:
    $key_4d9d = { 1a ef [2] 28 cd [2] 2e f8 [2] 00 f8 [2] 3f e4 }

  condition:
    any of them
}