rule TTP_XOR_WriteProcessMemory_8457 {
  strings:
    $key_8457 = { d3 25 [2] e1 07 [2] e7 32 [2] c9 32 [2] f6 2e }

  condition:
    any of them
}