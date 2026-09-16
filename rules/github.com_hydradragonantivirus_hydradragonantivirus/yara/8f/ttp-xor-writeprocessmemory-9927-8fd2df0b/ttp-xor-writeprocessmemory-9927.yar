rule TTP_XOR_WriteProcessMemory_9927 {
  strings:
    $key_9927 = { ce 55 [2] fc 77 [2] fa 42 [2] d4 42 [2] eb 5e }

  condition:
    any of them
}