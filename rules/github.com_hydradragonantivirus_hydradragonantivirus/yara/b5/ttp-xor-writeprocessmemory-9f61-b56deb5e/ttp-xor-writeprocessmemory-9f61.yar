rule TTP_XOR_WriteProcessMemory_9f61 {
  strings:
    $key_9f61 = { c8 13 [2] fa 31 [2] fc 04 [2] d2 04 [2] ed 18 }

  condition:
    any of them
}