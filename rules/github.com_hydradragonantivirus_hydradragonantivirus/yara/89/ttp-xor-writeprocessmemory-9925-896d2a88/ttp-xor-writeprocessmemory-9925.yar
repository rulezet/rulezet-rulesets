rule TTP_XOR_WriteProcessMemory_9925 {
  strings:
    $key_9925 = { ce 57 [2] fc 75 [2] fa 40 [2] d4 40 [2] eb 5c }

  condition:
    any of them
}