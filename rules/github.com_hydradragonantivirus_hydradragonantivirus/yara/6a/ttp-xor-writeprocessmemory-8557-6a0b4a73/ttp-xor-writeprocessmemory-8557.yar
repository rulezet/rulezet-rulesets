rule TTP_XOR_WriteProcessMemory_8557 {
  strings:
    $key_8557 = { d2 25 [2] e0 07 [2] e6 32 [2] c8 32 [2] f7 2e }

  condition:
    any of them
}