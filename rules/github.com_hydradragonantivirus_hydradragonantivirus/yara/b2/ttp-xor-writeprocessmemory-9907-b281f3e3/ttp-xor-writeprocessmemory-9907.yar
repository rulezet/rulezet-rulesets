rule TTP_XOR_WriteProcessMemory_9907 {
  strings:
    $key_9907 = { ce 75 [2] fc 57 [2] fa 62 [2] d4 62 [2] eb 7e }

  condition:
    any of them
}