rule TTP_XOR_WriteProcessMemory_92e3 {
  strings:
    $key_92e3 = { c5 91 [2] f7 b3 [2] f1 86 [2] df 86 [2] e0 9a }

  condition:
    any of them
}