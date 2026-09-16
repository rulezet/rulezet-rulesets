rule TTP_XOR_WriteProcessMemory_84ce {
  strings:
    $key_84ce = { d3 bc [2] e1 9e [2] e7 ab [2] c9 ab [2] f6 b7 }

  condition:
    any of them
}