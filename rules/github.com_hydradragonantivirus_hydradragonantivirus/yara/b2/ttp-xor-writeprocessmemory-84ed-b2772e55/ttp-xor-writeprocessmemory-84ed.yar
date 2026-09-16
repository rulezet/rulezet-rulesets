rule TTP_XOR_WriteProcessMemory_84ed {
  strings:
    $key_84ed = { d3 9f [2] e1 bd [2] e7 88 [2] c9 88 [2] f6 94 }

  condition:
    any of them
}