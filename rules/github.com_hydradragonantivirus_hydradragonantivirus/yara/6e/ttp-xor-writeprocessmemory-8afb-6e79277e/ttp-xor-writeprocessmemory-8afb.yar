rule TTP_XOR_WriteProcessMemory_8afb {
  strings:
    $key_8afb = { dd 89 [2] ef ab [2] e9 9e [2] c7 9e [2] f8 82 }

  condition:
    any of them
}