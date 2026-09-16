rule TTP_XOR_WriteProcessMemory_849c {
  strings:
    $key_849c = { d3 ee [2] e1 cc [2] e7 f9 [2] c9 f9 [2] f6 e5 }

  condition:
    any of them
}