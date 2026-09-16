rule TTP_XOR_WriteProcessMemory_9183 {
  strings:
    $key_9183 = { c6 f1 [2] f4 d3 [2] f2 e6 [2] dc e6 [2] e3 fa }

  condition:
    any of them
}