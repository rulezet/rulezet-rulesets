rule TTP_XOR_WriteProcessMemory_e49d {
  strings:
    $key_e49d = { b3 ef [2] 81 cd [2] 87 f8 [2] a9 f8 [2] 96 e4 }

  condition:
    any of them
}