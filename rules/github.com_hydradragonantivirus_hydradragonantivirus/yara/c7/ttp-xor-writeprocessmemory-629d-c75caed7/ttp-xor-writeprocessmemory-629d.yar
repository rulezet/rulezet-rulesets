rule TTP_XOR_WriteProcessMemory_629d {
  strings:
    $key_629d = { 35 ef [2] 07 cd [2] 01 f8 [2] 2f f8 [2] 10 e4 }

  condition:
    any of them
}