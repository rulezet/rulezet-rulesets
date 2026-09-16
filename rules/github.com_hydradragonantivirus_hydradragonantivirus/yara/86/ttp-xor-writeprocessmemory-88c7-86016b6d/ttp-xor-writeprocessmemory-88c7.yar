rule TTP_XOR_WriteProcessMemory_88c7 {
  strings:
    $key_88c7 = { df b5 [2] ed 97 [2] eb a2 [2] c5 a2 [2] fa be }

  condition:
    any of them
}