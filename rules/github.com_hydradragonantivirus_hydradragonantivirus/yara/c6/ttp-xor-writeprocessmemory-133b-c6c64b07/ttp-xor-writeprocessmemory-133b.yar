rule TTP_XOR_WriteProcessMemory_133b {
  strings:
    $key_133b = { 44 49 [2] 76 6b [2] 70 5e [2] 5e 5e [2] 61 42 }

  condition:
    any of them
}