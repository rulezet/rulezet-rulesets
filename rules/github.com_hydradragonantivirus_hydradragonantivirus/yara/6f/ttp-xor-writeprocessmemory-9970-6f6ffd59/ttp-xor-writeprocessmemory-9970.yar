rule TTP_XOR_WriteProcessMemory_9970 {
  strings:
    $key_9970 = { ce 02 [2] fc 20 [2] fa 15 [2] d4 15 [2] eb 09 }

  condition:
    any of them
}