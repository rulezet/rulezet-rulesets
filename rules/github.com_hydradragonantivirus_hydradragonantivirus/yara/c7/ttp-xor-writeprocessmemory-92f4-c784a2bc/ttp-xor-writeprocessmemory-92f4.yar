rule TTP_XOR_WriteProcessMemory_92f4 {
  strings:
    $key_92f4 = { c5 86 [2] f7 a4 [2] f1 91 [2] df 91 [2] e0 8d }

  condition:
    any of them
}