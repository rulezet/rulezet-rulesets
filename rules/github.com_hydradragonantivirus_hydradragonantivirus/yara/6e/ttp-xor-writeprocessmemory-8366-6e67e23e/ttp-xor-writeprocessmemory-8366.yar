rule TTP_XOR_WriteProcessMemory_8366 {
  strings:
    $key_8366 = { d4 14 [2] e6 36 [2] e0 03 [2] ce 03 [2] f1 1f }

  condition:
    any of them
}