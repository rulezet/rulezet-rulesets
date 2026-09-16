rule TTP_XOR_WriteProcessMemory_169d {
  strings:
    $key_169d = { 41 ef [2] 73 cd [2] 75 f8 [2] 5b f8 [2] 64 e4 }

  condition:
    any of them
}