rule TTP_XOR_WriteProcessMemory_99b7 {
  strings:
    $key_99b7 = { ce c5 [2] fc e7 [2] fa d2 [2] d4 d2 [2] eb ce }

  condition:
    any of them
}