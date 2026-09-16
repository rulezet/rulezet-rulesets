rule TTP_XOR_WriteProcessMemory_882c {
  strings:
    $key_882c = { df 5e [2] ed 7c [2] eb 49 [2] c5 49 [2] fa 55 }

  condition:
    any of them
}