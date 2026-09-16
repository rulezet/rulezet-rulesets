rule TTP_XOR_WriteProcessMemory_9924 {
  strings:
    $key_9924 = { ce 56 [2] fc 74 [2] fa 41 [2] d4 41 [2] eb 5d }

  condition:
    any of them
}