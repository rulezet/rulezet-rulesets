rule TTP_XOR_WriteProcessMemory_9182 {
  strings:
    $key_9182 = { c6 f0 [2] f4 d2 [2] f2 e7 [2] dc e7 [2] e3 fb }

  condition:
    any of them
}