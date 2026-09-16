rule TTP_XOR_WriteProcessMemory_83fd {
  strings:
    $key_83fd = { d4 8f [2] e6 ad [2] e0 98 [2] ce 98 [2] f1 84 }

  condition:
    any of them
}