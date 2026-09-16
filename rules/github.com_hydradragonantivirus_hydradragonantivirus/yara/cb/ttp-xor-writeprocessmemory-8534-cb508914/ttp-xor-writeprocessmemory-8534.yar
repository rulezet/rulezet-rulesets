rule TTP_XOR_WriteProcessMemory_8534 {
  strings:
    $key_8534 = { d2 46 [2] e0 64 [2] e6 51 [2] c8 51 [2] f7 4d }

  condition:
    any of them
}