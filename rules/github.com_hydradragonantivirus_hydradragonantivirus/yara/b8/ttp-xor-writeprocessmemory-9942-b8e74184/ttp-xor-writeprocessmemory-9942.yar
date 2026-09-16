rule TTP_XOR_WriteProcessMemory_9942 {
  strings:
    $key_9942 = { ce 30 [2] fc 12 [2] fa 27 [2] d4 27 [2] eb 3b }

  condition:
    any of them
}