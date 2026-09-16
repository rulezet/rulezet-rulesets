rule TTP_XOR_WriteProcessMemory_8aed {
  strings:
    $key_8aed = { dd 9f [2] ef bd [2] e9 88 [2] c7 88 [2] f8 94 }

  condition:
    any of them
}