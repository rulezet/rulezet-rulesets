rule TTP_XOR_WriteProcessMemory_8387 {
  strings:
    $key_8387 = { d4 f5 [2] e6 d7 [2] e0 e2 [2] ce e2 [2] f1 fe }

  condition:
    any of them
}