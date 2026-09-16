rule TTP_XOR_WriteProcessMemory_8123 {
  strings:
    $key_8123 = { d6 51 [2] e4 73 [2] e2 46 [2] cc 46 [2] f3 5a }

  condition:
    any of them
}