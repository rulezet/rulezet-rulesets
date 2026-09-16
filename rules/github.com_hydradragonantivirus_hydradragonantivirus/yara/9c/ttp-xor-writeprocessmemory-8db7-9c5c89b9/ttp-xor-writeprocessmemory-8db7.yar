rule TTP_XOR_WriteProcessMemory_8db7 {
  strings:
    $key_8db7 = { da c5 [2] e8 e7 [2] ee d2 [2] c0 d2 [2] ff ce }

  condition:
    any of them
}