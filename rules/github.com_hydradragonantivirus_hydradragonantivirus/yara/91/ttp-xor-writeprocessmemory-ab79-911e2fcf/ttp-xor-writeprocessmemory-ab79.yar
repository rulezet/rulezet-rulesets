rule TTP_XOR_WriteProcessMemory_ab79 {
  strings:
    $key_ab79 = { fc 0b [2] ce 29 [2] c8 1c [2] e6 1c [2] d9 00 }

  condition:
    any of them
}