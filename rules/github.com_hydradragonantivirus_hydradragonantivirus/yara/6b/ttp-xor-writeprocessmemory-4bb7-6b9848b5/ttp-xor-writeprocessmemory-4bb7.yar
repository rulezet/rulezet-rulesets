rule TTP_XOR_WriteProcessMemory_4bb7 {
  strings:
    $key_4bb7 = { 1c c5 [2] 2e e7 [2] 28 d2 [2] 06 d2 [2] 39 ce }

  condition:
    any of them
}