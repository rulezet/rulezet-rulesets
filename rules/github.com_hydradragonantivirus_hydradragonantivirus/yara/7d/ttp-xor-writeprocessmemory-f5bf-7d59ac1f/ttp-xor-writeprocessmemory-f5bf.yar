rule TTP_XOR_WriteProcessMemory_f5bf {
  strings:
    $key_f5bf = { a2 cd [2] 90 ef [2] 96 da [2] b8 da [2] 87 c6 }

  condition:
    any of them
}