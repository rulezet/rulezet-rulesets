rule TTP_XOR_WriteProcessMemory_9028 {
  strings:
    $key_9028 = { c7 5a [2] f5 78 [2] f3 4d [2] dd 4d [2] e2 51 }

  condition:
    any of them
}