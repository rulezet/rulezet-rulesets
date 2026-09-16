rule TTP_XOR_WriteProcessMemory_833d {
  strings:
    $key_833d = { d4 4f [2] e6 6d [2] e0 58 [2] ce 58 [2] f1 44 }

  condition:
    any of them
}