rule TTP_XOR_WriteProcessMemory_9455 {
  strings:
    $key_9455 = { c3 27 [2] f1 05 [2] f7 30 [2] d9 30 [2] e6 2c }

  condition:
    any of them
}