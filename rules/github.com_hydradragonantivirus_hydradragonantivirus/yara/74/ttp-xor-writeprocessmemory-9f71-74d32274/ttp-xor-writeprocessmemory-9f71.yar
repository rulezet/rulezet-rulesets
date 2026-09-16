rule TTP_XOR_WriteProcessMemory_9f71 {
  strings:
    $key_9f71 = { c8 03 [2] fa 21 [2] fc 14 [2] d2 14 [2] ed 08 }

  condition:
    any of them
}