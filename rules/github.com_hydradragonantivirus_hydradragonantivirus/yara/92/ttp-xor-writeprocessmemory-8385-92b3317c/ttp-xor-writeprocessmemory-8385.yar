rule TTP_XOR_WriteProcessMemory_8385 {
  strings:
    $key_8385 = { d4 f7 [2] e6 d5 [2] e0 e0 [2] ce e0 [2] f1 fc }

  condition:
    any of them
}