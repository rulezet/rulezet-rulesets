rule TTP_XOR_WriteProcessMemory_883b {
  strings:
    $key_883b = { df 49 [2] ed 6b [2] eb 5e [2] c5 5e [2] fa 42 }

  condition:
    any of them
}