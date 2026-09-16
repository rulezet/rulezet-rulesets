rule TTP_XOR_WriteProcessMemory_9939 {
  strings:
    $key_9939 = { ce 4b [2] fc 69 [2] fa 5c [2] d4 5c [2] eb 40 }

  condition:
    any of them
}