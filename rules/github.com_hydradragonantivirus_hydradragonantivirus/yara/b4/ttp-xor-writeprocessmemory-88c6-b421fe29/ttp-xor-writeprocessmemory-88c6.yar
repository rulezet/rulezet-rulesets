rule TTP_XOR_WriteProcessMemory_88c6 {
  strings:
    $key_88c6 = { df b4 [2] ed 96 [2] eb a3 [2] c5 a3 [2] fa bf }

  condition:
    any of them
}