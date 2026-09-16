rule TTP_XOR_WriteProcessMemory_9909 {
  strings:
    $key_9909 = { ce 7b [2] fc 59 [2] fa 6c [2] d4 6c [2] eb 70 }

  condition:
    any of them
}