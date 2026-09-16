rule TTP_XOR_WriteProcessMemory_7994 {
  strings:
    $key_7994 = { 2e e6 [2] 1c c4 [2] 1a f1 [2] 34 f1 [2] 0b ed }

  condition:
    any of them
}