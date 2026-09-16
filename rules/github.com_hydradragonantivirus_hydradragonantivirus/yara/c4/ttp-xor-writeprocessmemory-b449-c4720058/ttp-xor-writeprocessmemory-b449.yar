rule TTP_XOR_WriteProcessMemory_b449 {
  strings:
    $key_b449 = { e3 3b [2] d1 19 [2] d7 2c [2] f9 2c [2] c6 30 }

  condition:
    any of them
}