rule TTP_XOR_WriteProcessMemory_8339 {
  strings:
    $key_8339 = { d4 4b [2] e6 69 [2] e0 5c [2] ce 5c [2] f1 40 }

  condition:
    any of them
}