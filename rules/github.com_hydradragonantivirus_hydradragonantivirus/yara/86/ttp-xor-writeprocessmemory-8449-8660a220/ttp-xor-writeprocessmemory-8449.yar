rule TTP_XOR_WriteProcessMemory_8449 {
  strings:
    $key_8449 = { d3 3b [2] e1 19 [2] e7 2c [2] c9 2c [2] f6 30 }

  condition:
    any of them
}