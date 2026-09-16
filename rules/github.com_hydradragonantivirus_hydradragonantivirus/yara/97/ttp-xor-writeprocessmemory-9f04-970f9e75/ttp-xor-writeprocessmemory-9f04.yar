rule TTP_XOR_WriteProcessMemory_9f04 {
  strings:
    $key_9f04 = { c8 76 [2] fa 54 [2] fc 61 [2] d2 61 [2] ed 7d }

  condition:
    any of them
}