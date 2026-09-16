rule TTP_XOR_WriteProcessMemory_84f4 {
  strings:
    $key_84f4 = { d3 86 [2] e1 a4 [2] e7 91 [2] c9 91 [2] f6 8d }

  condition:
    any of them
}