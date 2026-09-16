rule TTP_XOR_WriteProcessMemory_bcc0 {
  strings:
    $key_bcc0 = { eb b2 [2] d9 90 [2] df a5 [2] f1 a5 [2] ce b9 }

  condition:
    any of them
}