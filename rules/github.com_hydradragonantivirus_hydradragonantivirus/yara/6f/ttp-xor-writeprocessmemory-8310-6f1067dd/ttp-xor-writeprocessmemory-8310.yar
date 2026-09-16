rule TTP_XOR_WriteProcessMemory_8310 {
  strings:
    $key_8310 = { d4 62 [2] e6 40 [2] e0 75 [2] ce 75 [2] f1 69 }

  condition:
    any of them
}