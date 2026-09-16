rule TTP_XOR_WriteProcessMemory_8287 {
  strings:
    $key_8287 = { d5 f5 [2] e7 d7 [2] e1 e2 [2] cf e2 [2] f0 fe }

  condition:
    any of them
}