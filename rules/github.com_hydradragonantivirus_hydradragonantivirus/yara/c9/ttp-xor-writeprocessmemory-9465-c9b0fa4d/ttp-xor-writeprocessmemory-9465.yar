rule TTP_XOR_WriteProcessMemory_9465 {
  strings:
    $key_9465 = { c3 17 [2] f1 35 [2] f7 00 [2] d9 00 [2] e6 1c }

  condition:
    any of them
}