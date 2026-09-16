rule TTP_XOR_WriteProcessMemory_8181 {
  strings:
    $key_8181 = { d6 f3 [2] e4 d1 [2] e2 e4 [2] cc e4 [2] f3 f8 }

  condition:
    any of them
}