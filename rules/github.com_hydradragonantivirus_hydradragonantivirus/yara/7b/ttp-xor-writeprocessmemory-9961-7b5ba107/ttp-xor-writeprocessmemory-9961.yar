rule TTP_XOR_WriteProcessMemory_9961 {
  strings:
    $key_9961 = { ce 13 [2] fc 31 [2] fa 04 [2] d4 04 [2] eb 18 }

  condition:
    any of them
}