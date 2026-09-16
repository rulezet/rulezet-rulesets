rule TTP_XOR_WriteProcessMemory_837d {
  strings:
    $key_837d = { d4 0f [2] e6 2d [2] e0 18 [2] ce 18 [2] f1 04 }

  condition:
    any of them
}