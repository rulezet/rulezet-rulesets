rule TTP_XOR_WriteProcessMemory_96fd {
  strings:
    $key_96fd = { c1 8f [2] f3 ad [2] f5 98 [2] db 98 [2] e4 84 }

  condition:
    any of them
}