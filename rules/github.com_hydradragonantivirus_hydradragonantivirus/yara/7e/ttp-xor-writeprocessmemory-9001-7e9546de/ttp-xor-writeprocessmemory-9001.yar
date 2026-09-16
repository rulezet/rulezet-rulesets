rule TTP_XOR_WriteProcessMemory_9001 {
  strings:
    $key_9001 = { c7 73 [2] f5 51 [2] f3 64 [2] dd 64 [2] e2 78 }

  condition:
    any of them
}