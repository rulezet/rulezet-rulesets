rule TTP_XOR_WriteProcessMemory_8efb {
  strings:
    $key_8efb = { d9 89 [2] eb ab [2] ed 9e [2] c3 9e [2] fc 82 }

  condition:
    any of them
}