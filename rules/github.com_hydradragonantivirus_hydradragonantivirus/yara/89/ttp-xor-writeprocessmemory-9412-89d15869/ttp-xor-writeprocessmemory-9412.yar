rule TTP_XOR_WriteProcessMemory_9412 {
  strings:
    $key_9412 = { c3 60 [2] f1 42 [2] f7 77 [2] d9 77 [2] e6 6b }

  condition:
    any of them
}