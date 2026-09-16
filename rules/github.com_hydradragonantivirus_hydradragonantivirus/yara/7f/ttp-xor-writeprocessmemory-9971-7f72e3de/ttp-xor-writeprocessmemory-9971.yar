rule TTP_XOR_WriteProcessMemory_9971 {
  strings:
    $key_9971 = { ce 03 [2] fc 21 [2] fa 14 [2] d4 14 [2] eb 08 }

  condition:
    any of them
}