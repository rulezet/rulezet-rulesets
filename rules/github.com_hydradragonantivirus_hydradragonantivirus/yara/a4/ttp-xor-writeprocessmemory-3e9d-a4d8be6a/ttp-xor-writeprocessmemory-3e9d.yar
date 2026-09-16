rule TTP_XOR_WriteProcessMemory_3e9d {
  strings:
    $key_3e9d = { 69 ef [2] 5b cd [2] 5d f8 [2] 73 f8 [2] 4c e4 }

  condition:
    any of them
}