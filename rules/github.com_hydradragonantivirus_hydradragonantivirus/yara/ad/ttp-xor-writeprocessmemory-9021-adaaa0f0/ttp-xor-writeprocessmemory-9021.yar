rule TTP_XOR_WriteProcessMemory_9021 {
  strings:
    $key_9021 = { c7 53 [2] f5 71 [2] f3 44 [2] dd 44 [2] e2 58 }

  condition:
    any of them
}