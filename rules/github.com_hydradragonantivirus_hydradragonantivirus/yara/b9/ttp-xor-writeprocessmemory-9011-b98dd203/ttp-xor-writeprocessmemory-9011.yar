rule TTP_XOR_WriteProcessMemory_9011 {
  strings:
    $key_9011 = { c7 63 [2] f5 41 [2] f3 74 [2] dd 74 [2] e2 68 }

  condition:
    any of them
}