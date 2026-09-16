rule TTP_XOR_WriteProcessMemory_639d {
  strings:
    $key_639d = { 34 ef [2] 06 cd [2] 00 f8 [2] 2e f8 [2] 11 e4 }

  condition:
    any of them
}