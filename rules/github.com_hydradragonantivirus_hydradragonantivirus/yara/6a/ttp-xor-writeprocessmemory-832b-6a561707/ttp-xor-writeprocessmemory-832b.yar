rule TTP_XOR_WriteProcessMemory_832b {
  strings:
    $key_832b = { d4 59 [2] e6 7b [2] e0 4e [2] ce 4e [2] f1 52 }

  condition:
    any of them
}