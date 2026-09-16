rule TTP_XOR_WriteProcessMemory_83dc {
  strings:
    $key_83dc = { d4 ae [2] e6 8c [2] e0 b9 [2] ce b9 [2] f1 a5 }

  condition:
    any of them
}