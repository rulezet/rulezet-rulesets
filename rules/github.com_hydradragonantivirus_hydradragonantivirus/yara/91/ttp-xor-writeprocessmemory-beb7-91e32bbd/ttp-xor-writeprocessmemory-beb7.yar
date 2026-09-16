rule TTP_XOR_WriteProcessMemory_beb7 {
  strings:
    $key_beb7 = { e9 c5 [2] db e7 [2] dd d2 [2] f3 d2 [2] cc ce }

  condition:
    any of them
}