rule TTP_XOR_WriteProcessMemory_9419 {
  strings:
    $key_9419 = { c3 6b [2] f1 49 [2] f7 7c [2] d9 7c [2] e6 60 }

  condition:
    any of them
}