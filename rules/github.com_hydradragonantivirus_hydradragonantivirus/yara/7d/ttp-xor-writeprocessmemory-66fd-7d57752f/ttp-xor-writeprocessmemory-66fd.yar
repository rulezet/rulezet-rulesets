rule TTP_XOR_WriteProcessMemory_66fd {
  strings:
    $key_66fd = { 31 8f [2] 03 ad [2] 05 98 [2] 2b 98 [2] 14 84 }

  condition:
    any of them
}