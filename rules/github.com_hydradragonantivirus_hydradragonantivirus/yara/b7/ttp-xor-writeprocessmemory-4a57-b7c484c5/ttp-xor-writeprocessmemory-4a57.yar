rule TTP_XOR_WriteProcessMemory_4a57 {
  strings:
    $key_4a57 = { 1d 25 [2] 2f 07 [2] 29 32 [2] 07 32 [2] 38 2e }

  condition:
    any of them
}