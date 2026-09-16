rule TTP_XOR_WriteProcessMemory_bcc8 {
  strings:
    $key_bcc8 = { eb ba [2] d9 98 [2] df ad [2] f1 ad [2] ce b1 }

  condition:
    any of them
}