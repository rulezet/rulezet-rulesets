rule TTP_XOR_WriteProcessMemory_a57b {
  strings:
    $key_a57b = { f2 09 [2] c0 2b [2] c6 1e [2] e8 1e [2] d7 02 }

  condition:
    any of them
}