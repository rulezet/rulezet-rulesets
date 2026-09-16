rule TTP_XOR_WriteProcessMemory_8386 {
  strings:
    $key_8386 = { d4 f4 [2] e6 d6 [2] e0 e3 [2] ce e3 [2] f1 ff }

  condition:
    any of them
}