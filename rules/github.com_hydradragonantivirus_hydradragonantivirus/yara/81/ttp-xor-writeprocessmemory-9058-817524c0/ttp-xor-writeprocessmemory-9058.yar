rule TTP_XOR_WriteProcessMemory_9058 {
  strings:
    $key_9058 = { c7 2a [2] f5 08 [2] f3 3d [2] dd 3d [2] e2 21 }

  condition:
    any of them
}