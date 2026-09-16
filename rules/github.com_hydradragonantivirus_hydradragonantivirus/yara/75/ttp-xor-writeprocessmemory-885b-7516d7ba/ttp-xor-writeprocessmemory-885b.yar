rule TTP_XOR_WriteProcessMemory_885b {
  strings:
    $key_885b = { df 29 [2] ed 0b [2] eb 3e [2] c5 3e [2] fa 22 }

  condition:
    any of them
}