rule TTP_XOR_WriteProcessMemory_9974 {
  strings:
    $key_9974 = { ce 06 [2] fc 24 [2] fa 11 [2] d4 11 [2] eb 0d }

  condition:
    any of them
}