rule TTP_XOR_WriteProcessMemory_f79d {
  strings:
    $key_f79d = { a0 ef [2] 92 cd [2] 94 f8 [2] ba f8 [2] 85 e4 }

  condition:
    any of them
}