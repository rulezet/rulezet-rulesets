rule TTP_XOR_WriteProcessMemory_bcc6 {
  strings:
    $key_bcc6 = { eb b4 [2] d9 96 [2] df a3 [2] f1 a3 [2] ce bf }

  condition:
    any of them
}