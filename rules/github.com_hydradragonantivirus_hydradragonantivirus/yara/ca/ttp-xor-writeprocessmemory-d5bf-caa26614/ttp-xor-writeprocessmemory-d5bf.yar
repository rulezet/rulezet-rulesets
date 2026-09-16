rule TTP_XOR_WriteProcessMemory_d5bf {
  strings:
    $key_d5bf = { 82 cd [2] b0 ef [2] b6 da [2] 98 da [2] a7 c6 }

  condition:
    any of them
}