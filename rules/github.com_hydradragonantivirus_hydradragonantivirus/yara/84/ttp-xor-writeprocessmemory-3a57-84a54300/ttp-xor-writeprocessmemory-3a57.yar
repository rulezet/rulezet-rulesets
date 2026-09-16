rule TTP_XOR_WriteProcessMemory_3a57 {
  strings:
    $key_3a57 = { 6d 25 [2] 5f 07 [2] 59 32 [2] 77 32 [2] 48 2e }

  condition:
    any of them
}