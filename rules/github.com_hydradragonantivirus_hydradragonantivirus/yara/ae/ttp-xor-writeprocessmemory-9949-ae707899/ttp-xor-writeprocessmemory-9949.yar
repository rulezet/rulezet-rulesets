rule TTP_XOR_WriteProcessMemory_9949 {
  strings:
    $key_9949 = { ce 3b [2] fc 19 [2] fa 2c [2] d4 2c [2] eb 30 }

  condition:
    any of them
}