rule TTP_XOR_WriteProcessMemory_9928 {
  strings:
    $key_9928 = { ce 5a [2] fc 78 [2] fa 4d [2] d4 4d [2] eb 51 }

  condition:
    any of them
}