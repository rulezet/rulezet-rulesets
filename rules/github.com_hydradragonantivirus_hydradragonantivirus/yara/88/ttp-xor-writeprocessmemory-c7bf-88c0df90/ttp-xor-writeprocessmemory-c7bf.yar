rule TTP_XOR_WriteProcessMemory_c7bf {
  strings:
    $key_c7bf = { 90 cd [2] a2 ef [2] a4 da [2] 8a da [2] b5 c6 }

  condition:
    any of them
}