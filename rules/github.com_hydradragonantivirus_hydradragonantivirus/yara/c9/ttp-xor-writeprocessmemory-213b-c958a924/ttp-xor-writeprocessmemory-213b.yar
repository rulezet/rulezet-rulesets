rule TTP_XOR_WriteProcessMemory_213b {
  strings:
    $key_213b = { 76 49 [2] 44 6b [2] 42 5e [2] 6c 5e [2] 53 42 }

  condition:
    any of them
}