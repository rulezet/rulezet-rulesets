rule TTP_XOR_WriteProcessMemory_59bf {
  strings:
    $key_59bf = { 0e cd [2] 3c ef [2] 3a da [2] 14 da [2] 2b c6 }

  condition:
    any of them
}