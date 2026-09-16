rule TTP_XOR_WriteProcessMemory_509d {
  strings:
    $key_509d = { 07 ef [2] 35 cd [2] 33 f8 [2] 1d f8 [2] 22 e4 }

  condition:
    any of them
}