rule TTP_XOR_WriteProcessMemory_099d {
  strings:
    $key_099d = { 5e ef [2] 6c cd [2] 6a f8 [2] 44 f8 [2] 7b e4 }

  condition:
    any of them
}