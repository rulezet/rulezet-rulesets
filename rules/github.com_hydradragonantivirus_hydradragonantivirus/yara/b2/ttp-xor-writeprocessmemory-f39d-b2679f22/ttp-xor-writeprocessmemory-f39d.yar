rule TTP_XOR_WriteProcessMemory_f39d {
  strings:
    $key_f39d = { a4 ef [2] 96 cd [2] 90 f8 [2] be f8 [2] 81 e4 }

  condition:
    any of them
}