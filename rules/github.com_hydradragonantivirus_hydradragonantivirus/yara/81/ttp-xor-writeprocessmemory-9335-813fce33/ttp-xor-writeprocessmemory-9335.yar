rule TTP_XOR_WriteProcessMemory_9335 {
  strings:
    $key_9335 = { c4 47 [2] f6 65 [2] f0 50 [2] de 50 [2] e1 4c }

  condition:
    any of them
}