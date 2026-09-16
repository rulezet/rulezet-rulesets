rule TTP_XOR_WriteProcessMemory_9943 {
  strings:
    $key_9943 = { ce 31 [2] fc 13 [2] fa 26 [2] d4 26 [2] eb 3a }

  condition:
    any of them
}