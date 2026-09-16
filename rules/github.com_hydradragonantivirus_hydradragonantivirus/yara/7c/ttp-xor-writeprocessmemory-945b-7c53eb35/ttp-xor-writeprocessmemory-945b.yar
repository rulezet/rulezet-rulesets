rule TTP_XOR_WriteProcessMemory_945b {
  strings:
    $key_945b = { c3 29 [2] f1 0b [2] f7 3e [2] d9 3e [2] e6 22 }

  condition:
    any of them
}