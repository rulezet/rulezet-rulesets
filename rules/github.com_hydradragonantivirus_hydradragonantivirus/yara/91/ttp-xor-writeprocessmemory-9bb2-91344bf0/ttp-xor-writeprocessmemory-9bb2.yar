rule TTP_XOR_WriteProcessMemory_9bb2 {
  strings:
    $key_9bb2 = { cc c0 [2] fe e2 [2] f8 d7 [2] d6 d7 [2] e9 cb }

  condition:
    any of them
}