rule TTP_XOR_WriteProcessMemory_7a57 {
  strings:
    $key_7a57 = { 2d 25 [2] 1f 07 [2] 19 32 [2] 37 32 [2] 08 2e }

  condition:
    any of them
}