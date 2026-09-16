rule TTP_XOR_WriteProcessMemory_884c {
  strings:
    $key_884c = { df 3e [2] ed 1c [2] eb 29 [2] c5 29 [2] fa 35 }

  condition:
    any of them
}