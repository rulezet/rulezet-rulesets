rule TTP_XOR_WriteProcessMemory_9fb7 {
  strings:
    $key_9fb7 = { c8 c5 [2] fa e7 [2] fc d2 [2] d2 d2 [2] ed ce }

  condition:
    any of them
}