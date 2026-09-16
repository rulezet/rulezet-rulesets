rule TTP_XOR_WriteProcessMemory_8555 {
  strings:
    $key_8555 = { d2 27 [2] e0 05 [2] e6 30 [2] c8 30 [2] f7 2c }

  condition:
    any of them
}