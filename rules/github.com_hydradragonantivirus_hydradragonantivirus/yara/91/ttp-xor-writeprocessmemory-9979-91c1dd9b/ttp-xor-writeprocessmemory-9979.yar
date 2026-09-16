rule TTP_XOR_WriteProcessMemory_9979 {
  strings:
    $key_9979 = { ce 0b [2] fc 29 [2] fa 1c [2] d4 1c [2] eb 00 }

  condition:
    any of them
}