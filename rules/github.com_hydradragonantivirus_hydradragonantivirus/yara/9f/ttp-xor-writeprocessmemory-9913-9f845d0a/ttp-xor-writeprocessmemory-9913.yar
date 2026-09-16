rule TTP_XOR_WriteProcessMemory_9913 {
  strings:
    $key_9913 = { ce 61 [2] fc 43 [2] fa 76 [2] d4 76 [2] eb 6a }

  condition:
    any of them
}