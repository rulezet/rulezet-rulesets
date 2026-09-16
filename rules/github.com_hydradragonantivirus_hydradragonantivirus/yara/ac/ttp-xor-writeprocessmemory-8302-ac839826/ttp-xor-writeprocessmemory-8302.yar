rule TTP_XOR_WriteProcessMemory_8302 {
  strings:
    $key_8302 = { d4 70 [2] e6 52 [2] e0 67 [2] ce 67 [2] f1 7b }

  condition:
    any of them
}