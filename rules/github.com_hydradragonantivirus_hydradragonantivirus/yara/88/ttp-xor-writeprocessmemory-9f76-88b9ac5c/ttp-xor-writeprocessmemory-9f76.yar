rule TTP_XOR_WriteProcessMemory_9f76 {
  strings:
    $key_9f76 = { c8 04 [2] fa 26 [2] fc 13 [2] d2 13 [2] ed 0f }

  condition:
    any of them
}