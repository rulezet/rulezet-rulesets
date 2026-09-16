rule TTP_XOR_WriteProcessMemory_f7bf {
  strings:
    $key_f7bf = { a0 cd [2] 92 ef [2] 94 da [2] ba da [2] 85 c6 }

  condition:
    any of them
}