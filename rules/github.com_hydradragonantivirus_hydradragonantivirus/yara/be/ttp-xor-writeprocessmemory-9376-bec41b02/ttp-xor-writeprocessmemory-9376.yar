rule TTP_XOR_WriteProcessMemory_9376 {
  strings:
    $key_9376 = { c4 04 [2] f6 26 [2] f0 13 [2] de 13 [2] e1 0f }

  condition:
    any of them
}