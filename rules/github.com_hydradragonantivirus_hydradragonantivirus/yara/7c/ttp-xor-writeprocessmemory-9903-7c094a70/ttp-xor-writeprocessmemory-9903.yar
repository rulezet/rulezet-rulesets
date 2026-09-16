rule TTP_XOR_WriteProcessMemory_9903 {
  strings:
    $key_9903 = { ce 71 [2] fc 53 [2] fa 66 [2] d4 66 [2] eb 7a }

  condition:
    any of them
}