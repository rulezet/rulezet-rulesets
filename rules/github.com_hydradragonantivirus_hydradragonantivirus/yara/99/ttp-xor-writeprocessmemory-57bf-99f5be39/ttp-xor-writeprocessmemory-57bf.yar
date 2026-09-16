rule TTP_XOR_WriteProcessMemory_57bf {
  strings:
    $key_57bf = { 00 cd [2] 32 ef [2] 34 da [2] 1a da [2] 25 c6 }

  condition:
    any of them
}