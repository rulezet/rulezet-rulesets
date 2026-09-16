rule TTP_XOR_WriteProcessMemory_a57e {
  strings:
    $key_a57e = { f2 0c [2] c0 2e [2] c6 1b [2] e8 1b [2] d7 07 }

  condition:
    any of them
}