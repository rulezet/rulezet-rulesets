rule TTP_XOR_WriteProcessMemory_38b7 {
  strings:
    $key_38b7 = { 6f c5 [2] 5d e7 [2] 5b d2 [2] 75 d2 [2] 4a ce }

  condition:
    any of them
}