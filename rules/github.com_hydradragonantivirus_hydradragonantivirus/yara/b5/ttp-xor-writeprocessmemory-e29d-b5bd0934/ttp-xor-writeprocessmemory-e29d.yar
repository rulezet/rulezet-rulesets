rule TTP_XOR_WriteProcessMemory_e29d {
  strings:
    $key_e29d = { b5 ef [2] 87 cd [2] 81 f8 [2] af f8 [2] 90 e4 }

  condition:
    any of them
}