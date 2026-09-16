rule TTP_XOR_WriteProcessMemory_8369 {
  strings:
    $key_8369 = { d4 1b [2] e6 39 [2] e0 0c [2] ce 0c [2] f1 10 }

  condition:
    any of them
}