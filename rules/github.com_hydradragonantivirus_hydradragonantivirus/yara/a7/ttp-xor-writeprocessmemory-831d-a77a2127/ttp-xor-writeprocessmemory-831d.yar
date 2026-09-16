rule TTP_XOR_WriteProcessMemory_831d {
  strings:
    $key_831d = { d4 6f [2] e6 4d [2] e0 78 [2] ce 78 [2] f1 64 }

  condition:
    any of them
}