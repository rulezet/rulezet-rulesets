rule TTP_XOR_WriteProcessMemory_129d {
  strings:
    $key_129d = { 45 ef [2] 77 cd [2] 71 f8 [2] 5f f8 [2] 60 e4 }

  condition:
    any of them
}