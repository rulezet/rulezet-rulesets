rule TTP_XOR_WriteProcessMemory_9bb0 {
  strings:
    $key_9bb0 = { cc c2 [2] fe e0 [2] f8 d5 [2] d6 d5 [2] e9 c9 }

  condition:
    any of them
}