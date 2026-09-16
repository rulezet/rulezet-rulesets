rule TTP_XOR_WriteProcessMemory_880c {
  strings:
    $key_880c = { df 7e [2] ed 5c [2] eb 69 [2] c5 69 [2] fa 75 }

  condition:
    any of them
}