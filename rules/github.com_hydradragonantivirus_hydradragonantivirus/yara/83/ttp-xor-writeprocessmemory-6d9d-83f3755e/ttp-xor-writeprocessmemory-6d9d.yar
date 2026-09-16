rule TTP_XOR_WriteProcessMemory_6d9d {
  strings:
    $key_6d9d = { 3a ef [2] 08 cd [2] 0e f8 [2] 20 f8 [2] 1f e4 }

  condition:
    any of them
}