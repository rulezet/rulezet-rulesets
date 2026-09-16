rule TTP_XOR_WriteProcessMemory_57fd {
  strings:
    $key_57fd = { 00 8f [2] 32 ad [2] 34 98 [2] 1a 98 [2] 25 84 }

  condition:
    any of them
}