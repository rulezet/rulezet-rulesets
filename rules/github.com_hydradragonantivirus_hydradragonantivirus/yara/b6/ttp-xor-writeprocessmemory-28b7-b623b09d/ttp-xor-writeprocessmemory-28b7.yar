rule TTP_XOR_WriteProcessMemory_28b7 {
  strings:
    $key_28b7 = { 7f c5 [2] 4d e7 [2] 4b d2 [2] 65 d2 [2] 5a ce }

  condition:
    any of them
}