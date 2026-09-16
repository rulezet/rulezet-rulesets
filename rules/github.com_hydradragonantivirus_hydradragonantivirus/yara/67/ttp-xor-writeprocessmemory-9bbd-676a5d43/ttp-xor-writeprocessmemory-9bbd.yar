rule TTP_XOR_WriteProcessMemory_9bbd {
  strings:
    $key_9bbd = { cc cf [2] fe ed [2] f8 d8 [2] d6 d8 [2] e9 c4 }

  condition:
    any of them
}