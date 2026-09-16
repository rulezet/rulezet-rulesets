rule TTP_XOR_WriteProcessMemory_9f03 {
  strings:
    $key_9f03 = { c8 71 [2] fa 53 [2] fc 66 [2] d2 66 [2] ed 7a }

  condition:
    any of them
}