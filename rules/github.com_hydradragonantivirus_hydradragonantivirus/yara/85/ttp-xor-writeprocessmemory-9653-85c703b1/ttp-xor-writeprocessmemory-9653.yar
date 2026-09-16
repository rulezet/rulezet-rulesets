rule TTP_XOR_WriteProcessMemory_9653 {
  strings:
    $key_9653 = { c1 21 [2] f3 03 [2] f5 36 [2] db 36 [2] e4 2a }

  condition:
    any of them
}