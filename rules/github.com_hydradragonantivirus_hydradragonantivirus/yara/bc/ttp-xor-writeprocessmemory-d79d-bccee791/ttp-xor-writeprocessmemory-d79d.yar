rule TTP_XOR_WriteProcessMemory_d79d {
  strings:
    $key_d79d = { 80 ef [2] b2 cd [2] b4 f8 [2] 9a f8 [2] a5 e4 }

  condition:
    any of them
}