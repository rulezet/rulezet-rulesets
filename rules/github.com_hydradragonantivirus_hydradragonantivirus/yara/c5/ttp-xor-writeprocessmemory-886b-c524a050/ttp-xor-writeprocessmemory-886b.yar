rule TTP_XOR_WriteProcessMemory_886b {
  strings:
    $key_886b = { df 19 [2] ed 3b [2] eb 0e [2] c5 0e [2] fa 12 }

  condition:
    any of them
}