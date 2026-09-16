rule TTP_XOR_WriteProcessMemory_8187 {
  strings:
    $key_8187 = { d6 f5 [2] e4 d7 [2] e2 e2 [2] cc e2 [2] f3 fe }

  condition:
    any of them
}