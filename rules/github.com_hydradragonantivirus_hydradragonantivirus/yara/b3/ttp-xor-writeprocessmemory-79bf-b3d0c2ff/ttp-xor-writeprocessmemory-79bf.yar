rule TTP_XOR_WriteProcessMemory_79bf {
  strings:
    $key_79bf = { 2e cd [2] 1c ef [2] 1a da [2] 34 da [2] 0b c6 }

  condition:
    any of them
}