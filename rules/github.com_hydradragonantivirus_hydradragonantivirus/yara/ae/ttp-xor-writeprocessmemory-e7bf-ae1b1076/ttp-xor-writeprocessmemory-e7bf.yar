rule TTP_XOR_WriteProcessMemory_e7bf {
  strings:
    $key_e7bf = { b0 cd [2] 82 ef [2] 84 da [2] aa da [2] 95 c6 }

  condition:
    any of them
}