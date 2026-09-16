rule TTP_XOR_WriteProcessMemory_bcc2 {
  strings:
    $key_bcc2 = { eb b0 [2] d9 92 [2] df a7 [2] f1 a7 [2] ce bb }

  condition:
    any of them
}