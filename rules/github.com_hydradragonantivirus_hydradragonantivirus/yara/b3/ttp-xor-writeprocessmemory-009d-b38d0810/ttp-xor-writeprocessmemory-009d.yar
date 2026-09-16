rule TTP_XOR_WriteProcessMemory_009d {
  strings:
    $key_009d = { 57 ef [2] 65 cd [2] 63 f8 [2] 4d f8 [2] 72 e4 }

  condition:
    any of them
}