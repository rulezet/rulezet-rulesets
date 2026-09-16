rule TTP_XOR_WriteProcessMemory_8304 {
  strings:
    $key_8304 = { d4 76 [2] e6 54 [2] e0 61 [2] ce 61 [2] f1 7d }

  condition:
    any of them
}