rule TTP_XOR_WriteProcessMemory_9bb1 {
  strings:
    $key_9bb1 = { cc c3 [2] fe e1 [2] f8 d4 [2] d6 d4 [2] e9 c8 }

  condition:
    any of them
}