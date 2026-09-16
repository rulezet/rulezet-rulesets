rule TTP_XOR_WriteProcessMemory_945c {
  strings:
    $key_945c = { c3 2e [2] f1 0c [2] f7 39 [2] d9 39 [2] e6 25 }

  condition:
    any of them
}