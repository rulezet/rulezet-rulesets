rule TTP_XOR_WriteProcessMemory_9d82 {
  strings:
    $key_9d82 = { ca f0 [2] f8 d2 [2] fe e7 [2] d0 e7 [2] ef fb }

  condition:
    any of them
}