rule TTP_XOR_WriteProcessMemory_f6bf {
  strings:
    $key_f6bf = { a1 cd [2] 93 ef [2] 95 da [2] bb da [2] 84 c6 }

  condition:
    any of them
}