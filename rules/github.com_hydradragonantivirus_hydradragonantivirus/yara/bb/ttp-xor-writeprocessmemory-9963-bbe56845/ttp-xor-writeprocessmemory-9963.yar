rule TTP_XOR_WriteProcessMemory_9963 {
  strings:
    $key_9963 = { ce 11 [2] fc 33 [2] fa 06 [2] d4 06 [2] eb 1a }

  condition:
    any of them
}