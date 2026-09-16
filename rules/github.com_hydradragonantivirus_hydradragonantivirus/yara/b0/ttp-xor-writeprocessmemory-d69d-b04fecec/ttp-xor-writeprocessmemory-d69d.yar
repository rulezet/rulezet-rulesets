rule TTP_XOR_WriteProcessMemory_d69d {
  strings:
    $key_d69d = { 81 ef [2] b3 cd [2] b5 f8 [2] 9b f8 [2] a4 e4 }

  condition:
    any of them
}