rule TTP_XOR_WriteProcessMemory_3aeb {
  strings:
    $key_3aeb = { 6d 99 [2] 5f bb [2] 59 8e [2] 77 8e [2] 48 92 }

  condition:
    any of them
}