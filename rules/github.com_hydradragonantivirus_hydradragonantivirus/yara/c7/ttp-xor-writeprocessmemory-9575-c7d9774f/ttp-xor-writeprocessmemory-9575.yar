rule TTP_XOR_WriteProcessMemory_9575 {
  strings:
    $key_9575 = { c2 07 [2] f0 25 [2] f6 10 [2] d8 10 [2] e7 0c }

  condition:
    any of them
}