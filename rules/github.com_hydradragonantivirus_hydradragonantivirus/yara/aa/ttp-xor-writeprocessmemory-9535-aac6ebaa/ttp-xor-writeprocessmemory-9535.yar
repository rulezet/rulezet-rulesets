rule TTP_XOR_WriteProcessMemory_9535 {
  strings:
    $key_9535 = { c2 47 [2] f0 65 [2] f6 50 [2] d8 50 [2] e7 4c }

  condition:
    any of them
}