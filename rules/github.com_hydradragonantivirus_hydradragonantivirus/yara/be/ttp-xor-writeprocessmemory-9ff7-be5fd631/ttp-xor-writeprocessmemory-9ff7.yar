rule TTP_XOR_WriteProcessMemory_9ff7 {
  strings:
    $key_9ff7 = { c8 85 [2] fa a7 [2] fc 92 [2] d2 92 [2] ed 8e }

  condition:
    any of them
}