rule TTP_XOR_WriteProcessMemory_329d {
  strings:
    $key_329d = { 65 ef [2] 57 cd [2] 51 f8 [2] 7f f8 [2] 40 e4 }

  condition:
    any of them
}