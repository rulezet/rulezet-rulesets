rule TTP_XOR_WriteProcessMemory_94fd {
  strings:
    $key_94fd = { c3 8f [2] f1 ad [2] f7 98 [2] d9 98 [2] e6 84 }

  condition:
    any of them
}