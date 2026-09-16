rule TTP_XOR_WriteProcessMemory_9a57 {
  strings:
    $key_9a57 = { cd 25 [2] ff 07 [2] f9 32 [2] d7 32 [2] e8 2e }

  condition:
    any of them
}