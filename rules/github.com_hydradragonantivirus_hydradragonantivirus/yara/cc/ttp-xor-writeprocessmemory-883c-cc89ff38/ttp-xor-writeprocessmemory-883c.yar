rule TTP_XOR_WriteProcessMemory_883c {
  strings:
    $key_883c = { df 4e [2] ed 6c [2] eb 59 [2] c5 59 [2] fa 45 }

  condition:
    any of them
}