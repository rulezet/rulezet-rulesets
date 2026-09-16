rule TTP_XOR_WriteProcessMemory_835d {
  strings:
    $key_835d = { d4 2f [2] e6 0d [2] e0 38 [2] ce 38 [2] f1 24 }

  condition:
    any of them
}