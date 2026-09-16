rule TTP_XOR_WriteProcessMemory_a57c {
  strings:
    $key_a57c = { f2 0e [2] c0 2c [2] c6 19 [2] e8 19 [2] d7 05 }

  condition:
    any of them
}