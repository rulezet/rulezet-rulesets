rule TTP_XOR_WriteProcessMemory_8493 {
  strings:
    $key_8493 = { d3 e1 [2] e1 c3 [2] e7 f6 [2] c9 f6 [2] f6 ea }

  condition:
    any of them
}