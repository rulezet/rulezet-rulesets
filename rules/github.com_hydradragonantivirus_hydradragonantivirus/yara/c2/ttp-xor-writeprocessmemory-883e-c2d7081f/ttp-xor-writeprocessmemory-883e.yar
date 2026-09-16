rule TTP_XOR_WriteProcessMemory_883e {
  strings:
    $key_883e = { df 4c [2] ed 6e [2] eb 5b [2] c5 5b [2] fa 47 }

  condition:
    any of them
}