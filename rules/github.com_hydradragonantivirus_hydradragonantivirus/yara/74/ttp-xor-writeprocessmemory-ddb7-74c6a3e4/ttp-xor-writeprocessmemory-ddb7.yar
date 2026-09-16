rule TTP_XOR_WriteProcessMemory_ddb7 {
  strings:
    $key_ddb7 = { 8a c5 [2] b8 e7 [2] be d2 [2] 90 d2 [2] af ce }

  condition:
    any of them
}