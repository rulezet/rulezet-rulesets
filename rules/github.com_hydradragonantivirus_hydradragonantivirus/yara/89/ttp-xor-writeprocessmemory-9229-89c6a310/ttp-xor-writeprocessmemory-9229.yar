rule TTP_XOR_WriteProcessMemory_9229 {
  strings:
    $key_9229 = { c5 5b [2] f7 79 [2] f1 4c [2] df 4c [2] e0 50 }

  condition:
    any of them
}