rule TTP_XOR_WriteProcessMemory_8334 {
  strings:
    $key_8334 = { d4 46 [2] e6 64 [2] e0 51 [2] ce 51 [2] f1 4d }

  condition:
    any of them
}