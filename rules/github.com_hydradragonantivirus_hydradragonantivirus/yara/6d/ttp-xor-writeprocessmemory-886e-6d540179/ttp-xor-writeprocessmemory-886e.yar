rule TTP_XOR_WriteProcessMemory_886e {
  strings:
    $key_886e = { df 1c [2] ed 3e [2] eb 0b [2] c5 0b [2] fa 17 }

  condition:
    any of them
}