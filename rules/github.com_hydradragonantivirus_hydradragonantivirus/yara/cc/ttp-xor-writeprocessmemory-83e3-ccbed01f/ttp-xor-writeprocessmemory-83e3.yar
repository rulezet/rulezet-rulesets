rule TTP_XOR_WriteProcessMemory_83e3 {
  strings:
    $key_83e3 = { d4 91 [2] e6 b3 [2] e0 86 [2] ce 86 [2] f1 9a }

  condition:
    any of them
}