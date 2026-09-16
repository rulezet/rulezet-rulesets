rule TTP_XOR_WriteProcessMemory_9259 {
  strings:
    $key_9259 = { c5 2b [2] f7 09 [2] f1 3c [2] df 3c [2] e0 20 }

  condition:
    any of them
}