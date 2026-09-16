rule TTP_XOR_WriteProcessMemory_9201 {
  strings:
    $key_9201 = { c5 73 [2] f7 51 [2] f1 64 [2] df 64 [2] e0 78 }

  condition:
    any of them
}