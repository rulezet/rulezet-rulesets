rule TTP_XOR_WriteProcessMemory_843c {
  strings:
    $key_843c = { d3 4e [2] e1 6c [2] e7 59 [2] c9 59 [2] f6 45 }

  condition:
    any of them
}