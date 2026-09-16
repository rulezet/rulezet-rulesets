rule TTP_XOR_WriteProcessMemory_9965 {
  strings:
    $key_9965 = { ce 17 [2] fc 35 [2] fa 00 [2] d4 00 [2] eb 1c }

  condition:
    any of them
}