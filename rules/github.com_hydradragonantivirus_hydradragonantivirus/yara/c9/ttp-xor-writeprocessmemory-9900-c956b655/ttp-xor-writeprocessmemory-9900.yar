rule TTP_XOR_WriteProcessMemory_9900 {
  strings:
    $key_9900 = { ce 72 [2] fc 50 [2] fa 65 [2] d4 65 [2] eb 79 }

  condition:
    any of them
}