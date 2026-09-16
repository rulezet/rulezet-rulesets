rule TTP_XOR_WriteProcessMemory_f09d {
  strings:
    $key_f09d = { a7 ef [2] 95 cd [2] 93 f8 [2] bd f8 [2] 82 e4 }

  condition:
    any of them
}