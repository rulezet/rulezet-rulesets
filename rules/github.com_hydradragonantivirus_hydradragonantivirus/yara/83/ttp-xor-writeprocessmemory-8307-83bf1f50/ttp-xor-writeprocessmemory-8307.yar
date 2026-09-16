rule TTP_XOR_WriteProcessMemory_8307 {
  strings:
    $key_8307 = { d4 75 [2] e6 57 [2] e0 62 [2] ce 62 [2] f1 7e }

  condition:
    any of them
}