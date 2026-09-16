rule TTP_XOR_WriteProcessMemory_c09d {
  strings:
    $key_c09d = { 97 ef [2] a5 cd [2] a3 f8 [2] 8d f8 [2] b2 e4 }

  condition:
    any of them
}