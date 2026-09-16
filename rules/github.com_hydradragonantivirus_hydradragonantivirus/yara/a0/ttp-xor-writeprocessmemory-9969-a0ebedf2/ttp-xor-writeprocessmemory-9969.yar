rule TTP_XOR_WriteProcessMemory_9969 {
  strings:
    $key_9969 = { ce 1b [2] fc 39 [2] fa 0c [2] d4 0c [2] eb 10 }

  condition:
    any of them
}