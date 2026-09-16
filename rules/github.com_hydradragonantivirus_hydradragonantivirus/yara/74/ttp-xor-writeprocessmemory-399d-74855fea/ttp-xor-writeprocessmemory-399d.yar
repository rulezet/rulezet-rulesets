rule TTP_XOR_WriteProcessMemory_399d {
  strings:
    $key_399d = { 6e ef [2] 5c cd [2] 5a f8 [2] 74 f8 [2] 4b e4 }

  condition:
    any of them
}