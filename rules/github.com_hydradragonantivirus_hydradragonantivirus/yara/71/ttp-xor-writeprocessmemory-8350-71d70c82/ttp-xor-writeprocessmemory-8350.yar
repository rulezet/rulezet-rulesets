rule TTP_XOR_WriteProcessMemory_8350 {
  strings:
    $key_8350 = { d4 22 [2] e6 00 [2] e0 35 [2] ce 35 [2] f1 29 }

  condition:
    any of them
}