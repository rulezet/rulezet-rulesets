rule TTP_XOR_WriteProcessMemory_9948 {
  strings:
    $key_9948 = { ce 3a [2] fc 18 [2] fa 2d [2] d4 2d [2] eb 31 }

  condition:
    any of them
}