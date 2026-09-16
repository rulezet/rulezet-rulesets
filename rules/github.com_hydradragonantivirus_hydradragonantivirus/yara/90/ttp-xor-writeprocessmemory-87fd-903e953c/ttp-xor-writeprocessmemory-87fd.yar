rule TTP_XOR_WriteProcessMemory_87fd {
  strings:
    $key_87fd = { d0 8f [2] e2 ad [2] e4 98 [2] ca 98 [2] f5 84 }

  condition:
    any of them
}