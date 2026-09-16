rule TTP_XOR_WriteProcessMemory_9918 {
  strings:
    $key_9918 = { ce 6a [2] fc 48 [2] fa 7d [2] d4 7d [2] eb 61 }

  condition:
    any of them
}