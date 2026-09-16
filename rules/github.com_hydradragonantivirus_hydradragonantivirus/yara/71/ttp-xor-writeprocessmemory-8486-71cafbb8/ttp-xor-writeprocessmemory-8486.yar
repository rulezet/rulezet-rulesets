rule TTP_XOR_WriteProcessMemory_8486 {
  strings:
    $key_8486 = { d3 f4 [2] e1 d6 [2] e7 e3 [2] c9 e3 [2] f6 ff }

  condition:
    any of them
}