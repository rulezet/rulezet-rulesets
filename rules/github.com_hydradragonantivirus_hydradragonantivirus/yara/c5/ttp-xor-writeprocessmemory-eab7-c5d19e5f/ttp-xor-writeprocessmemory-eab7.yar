rule TTP_XOR_WriteProcessMemory_eab7 {
  strings:
    $key_eab7 = { bd c5 [2] 8f e7 [2] 89 d2 [2] a7 d2 [2] 98 ce }

  condition:
    any of them
}