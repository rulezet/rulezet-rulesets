rule TTP_XOR_WriteProcessMemory_9409 {
  strings:
    $key_9409 = { c3 7b [2] f1 59 [2] f7 6c [2] d9 6c [2] e6 70 }

  condition:
    any of them
}